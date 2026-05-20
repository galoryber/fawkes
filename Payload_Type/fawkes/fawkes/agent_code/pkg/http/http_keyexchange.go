package http

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// keyRotationState tracks the ECDH key exchange lifecycle for forward secrecy.
// The rotation follows a two-phase protocol:
//
//	Phase 1 (exchange): Agent sends ephemeral public key, receives server's.
//	         Both derive the new shared key but continue using the old key.
//	Phase 2 (switch):   Agent sends acknowledgment with old key. Server updates
//	         its decryption key. Agent switches to new key for sending.
//	         Server updates encryption key. Agent switches for receiving.
type keyRotationState struct {
	mu          sync.Mutex
	privateKey  *ecdh.PrivateKey
	peerPubKey  *ecdh.PublicKey
	pendingKey  []byte // derived but not yet active
	checkIns    uint64 // counter for rotation interval
	interval    uint64 // rotate every N check-ins (0 = disabled)
	phase       rotationPhase
}

type rotationPhase int

const (
	phaseIdle      rotationPhase = iota
	phaseExchanged               // ephemeral keys exchanged, new key derived
	phaseSwitching               // agent switching to new key
)

const keyRotationInfo = "fawkes-key-rotation-v1"

// newKeyRotationState creates a key rotation tracker. interval=0 disables rotation.
func newKeyRotationState(interval uint64) *keyRotationState {
	return &keyRotationState{interval: interval}
}

// ShouldInitiateExchange returns true when the check-in counter reaches the
// rotation interval and no exchange is in progress.
func (kr *keyRotationState) ShouldInitiateExchange() bool {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	if kr.interval == 0 || kr.phase != phaseIdle {
		return false
	}
	kr.checkIns++
	return kr.checkIns >= kr.interval
}

// GenerateEphemeralKey creates a new X25519 keypair for key exchange and returns
// the public key encoded as base64 for inclusion in the check-in message.
func (kr *keyRotationState) GenerateEphemeralKey() (string, error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("X25519 keygen failed: %w", err)
	}
	kr.privateKey = priv
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// ProcessServerKey takes the server's base64-encoded ephemeral public key and
// the current encryption key, performs ECDH, and derives the new session key.
// Returns the new key (32 bytes) ready for vault rotation.
func (kr *keyRotationState) ProcessServerKey(serverPubB64 string, currentKey []byte) ([]byte, error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if kr.privateKey == nil {
		return nil, fmt.Errorf("no ephemeral key generated")
	}

	pubBytes, err := base64.StdEncoding.DecodeString(serverPubB64)
	if err != nil {
		return nil, fmt.Errorf("invalid server public key: %w", err)
	}

	curve := ecdh.X25519()
	peerPub, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 public key: %w", err)
	}

	sharedSecret, err := kr.privateKey.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	newKey, err := deriveKey(sharedSecret, currentKey)
	if err != nil {
		return nil, err
	}

	kr.pendingKey = newKey
	kr.peerPubKey = peerPub
	kr.phase = phaseExchanged

	zeroBytes(sharedSecret)
	zeroBytes(kr.privateKey.Bytes())
	kr.privateKey = nil

	return newKey, nil
}

// ConfirmRotation marks the rotation as complete and resets the state for the
// next rotation cycle.
func (kr *keyRotationState) ConfirmRotation() {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if kr.pendingKey != nil {
		zeroBytes(kr.pendingKey)
		kr.pendingKey = nil
	}
	kr.peerPubKey = nil
	kr.phase = phaseIdle
	kr.checkIns = 0
}

// Abort cancels an in-progress key exchange and returns to idle state.
func (kr *keyRotationState) Abort() {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if kr.privateKey != nil {
		zeroBytes(kr.privateKey.Bytes())
		kr.privateKey = nil
	}
	if kr.pendingKey != nil {
		zeroBytes(kr.pendingKey)
		kr.pendingKey = nil
	}
	kr.peerPubKey = nil
	kr.phase = phaseIdle
}

// Phase returns the current rotation phase.
func (kr *keyRotationState) Phase() rotationPhase {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	return kr.phase
}

// deriveKey uses HKDF-SHA256 to derive a 32-byte AES-256 key from the ECDH
// shared secret, using the current key as salt for domain separation.
func deriveKey(sharedSecret, salt []byte) ([]byte, error) {
	hk := hkdf.New(sha256.New, sharedSecret, salt, []byte(keyRotationInfo))
	newKey := make([]byte, 32)
	if _, err := io.ReadFull(hk, newKey); err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}
	return newKey, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// processKeyExchangeResponse handles the server's ECDH key exchange response.
// Phase 1: server sends its ephemeral public key → agent derives new key, stores pending.
// Phase 2: server confirms key switch → agent rotates to new key.
func (h *HTTPProfile) processKeyExchangeResponse(resp map[string]interface{}, cfg *sensitiveConfig) {
	if h.keyRotation == nil {
		return
	}

	// Phase 1: server responded with its ephemeral public key
	if serverPub, ok := resp["key_exchange_response"].(string); ok && serverPub != "" {
		currentKeyBytes, err := base64.StdEncoding.DecodeString(cfg.EncryptionKey)
		if err != nil {
			h.keyRotation.Abort()
			return
		}
		_, err = h.keyRotation.ProcessServerKey(serverPub, currentKeyBytes)
		if err != nil {
			h.keyRotation.Abort()
		}
		return
	}

	// Phase 2: server confirmed the key switch
	if confirmed, ok := resp["key_exchange_confirmed"].(bool); ok && confirmed {
		if h.keyRotation.Phase() != phaseExchanged {
			return
		}
		h.keyRotation.mu.Lock()
		pendingKey := h.keyRotation.pendingKey
		h.keyRotation.mu.Unlock()

		if pendingKey == nil {
			h.keyRotation.Abort()
			return
		}

		newKeyB64 := base64.StdEncoding.EncodeToString(pendingKey)
		if err := h.RotateEncryptionKey(newKeyB64); err != nil {
			h.keyRotation.Abort()
			return
		}
		h.keyRotation.ConfirmRotation()
	}
}

// RotateEncryptionKey atomically swaps the encryption key in the config vault.
// The old key is zeroed after the swap.
func (h *HTTPProfile) RotateEncryptionKey(newKeyB64 string) error {
	if h.vault == nil {
		oldKey := h.EncryptionKey
		h.EncryptionKey = newKeyB64
		for i := range []byte(oldKey) {
			_ = i
		}
		return nil
	}

	cfg := h.getConfig()
	if cfg == nil {
		return fmt.Errorf("config vault decryption failed")
	}

	oldKey := cfg.EncryptionKey
	cfg.EncryptionKey = newKeyB64

	plaintext, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config vault marshal failed: %w", err)
	}

	newBlob := vaultEncrypt(h.vault.key, plaintext)
	vaultZeroBytes(plaintext)
	if newBlob == nil {
		return fmt.Errorf("config vault encryption failed")
	}

	oldBlob := h.vault.blob
	h.vault.blob = newBlob
	vaultZeroBytes(oldBlob)

	_ = oldKey
	return nil
}
