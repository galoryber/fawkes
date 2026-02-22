package commands

import (
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
	"fawkes/pkg/tcp"
)

// =============================================================================
// recvTCPFramed tests
// =============================================================================

func TestRecvTCPFramed_BasicMessage(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	payload := []byte("hello world")
	go func() {
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, uint32(len(payload)))
		server.Write(header)
		server.Write(payload)
	}()

	data, err := recvTCPFramed(client)
	if err != nil {
		t.Fatalf("recvTCPFramed error: %v", err)
	}
	if string(data) != "hello world" {
		t.Errorf("got %q, want %q", string(data), "hello world")
	}
}

func TestRecvTCPFramed_EmptyMessage(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, 0)
		server.Write(header)
	}()

	data, err := recvTCPFramed(client)
	if err != nil {
		t.Fatalf("recvTCPFramed error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(data))
	}
}

func TestRecvTCPFramed_OversizedMessage(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, 11*1024*1024) // > 10MB limit
		server.Write(header)
	}()

	_, err := recvTCPFramed(client)
	if err == nil {
		t.Fatal("expected error for oversized message")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected 'too large' error, got: %v", err)
	}
}

func TestRecvTCPFramed_ConnectionClosed(t *testing.T) {
	server, client := net.Pipe()
	server.Close() // Close immediately

	_, err := recvTCPFramed(client)
	if err == nil {
		t.Fatal("expected error for closed connection")
	}
	client.Close()
}

func TestRecvTCPFramed_PartialHeader(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		server.Write([]byte{0x00, 0x00}) // Only 2 of 4 header bytes
		server.Close()
	}()

	_, err := recvTCPFramed(client)
	if err == nil {
		t.Fatal("expected error for partial header")
	}
}

func TestRecvTCPFramed_PartialPayload(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, 100) // Claim 100 bytes
		server.Write(header)
		server.Write([]byte("only 10 by")) // Send only 10
		server.Close()
	}()

	_, err := recvTCPFramed(client)
	if err == nil {
		t.Fatal("expected error for partial payload")
	}
}

// =============================================================================
// LinkCommand tests
// =============================================================================

func TestLinkCommand_Name(t *testing.T) {
	cmd := &LinkCommand{}
	if cmd.Name() != "link" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "link")
	}
}

func TestLinkCommand_Description(t *testing.T) {
	cmd := &LinkCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestLinkCommand_InvalidJSON(t *testing.T) {
	cmd := &LinkCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Failed to parse") {
		t.Errorf("expected parse error, got: %s", result.Output)
	}
}

func TestLinkCommand_EmptyParams(t *testing.T) {
	cmd := &LinkCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "host and port are required") {
		t.Errorf("expected host/port required error, got: %s", result.Output)
	}
}

func TestLinkCommand_MissingHost(t *testing.T) {
	cmd := &LinkCommand{}
	task := structs.Task{Params: `{"port": 7777}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "host and port are required") {
		t.Errorf("expected host/port required error, got: %s", result.Output)
	}
}

func TestLinkCommand_MissingPort(t *testing.T) {
	cmd := &LinkCommand{}
	task := structs.Task{Params: `{"host": "10.0.0.1"}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "host and port are required") {
		t.Errorf("expected host/port required error, got: %s", result.Output)
	}
}

func TestLinkCommand_NoTCPProfile(t *testing.T) {
	// Ensure tcpProfileInstance is nil
	oldProfile := tcpProfileInstance
	tcpProfileInstance = nil
	defer func() { tcpProfileInstance = oldProfile }()

	cmd := &LinkCommand{}
	task := structs.Task{Params: `{"host": "10.0.0.1", "port": 7777}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "TCP P2P not available") {
		t.Errorf("expected TCP not available error, got: %s", result.Output)
	}
}

func TestLinkCommand_ConnectionRefused(t *testing.T) {
	// Use a port that's not listening
	profile := tcp.NewTCPProfile("", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false)
	profile.CallbackUUID = "parent-uuid-1234"
	oldProfile := tcpProfileInstance
	tcpProfileInstance = profile
	defer func() { tcpProfileInstance = oldProfile }()

	cmd := &LinkCommand{}
	task := structs.Task{Params: `{"host": "127.0.0.1", "port": 1}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Failed to connect") {
		t.Errorf("expected connection error, got: %s", result.Output)
	}
}

func TestLinkCommand_InvalidCheckinData(t *testing.T) {
	// Start a mock child that sends non-base64 data
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Send framed but non-base64 data
		payload := []byte("!!!not-base64!!!")
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, uint32(len(payload)))
		conn.Write(header)
		conn.Write(payload)
		// Keep connection alive briefly for test
		time.Sleep(100 * time.Millisecond)
	}()

	profile := tcp.NewTCPProfile("", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false)
	profile.CallbackUUID = "parent-uuid-1234"
	oldProfile := tcpProfileInstance
	tcpProfileInstance = profile
	defer func() { tcpProfileInstance = oldProfile }()

	cmd := &LinkCommand{}
	task := structs.Task{Params: `{"host": "127.0.0.1", "port": ` + itoa(port) + `}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Invalid checkin data") {
		t.Errorf("expected invalid checkin error, got: %s", result.Output)
	}
}

func TestLinkCommand_ShortCheckinData(t *testing.T) {
	// Send valid base64 but too short to contain a UUID (< 36 bytes decoded)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// base64 of "short" = 5 bytes, way less than 36
		payload := []byte(base64.StdEncoding.EncodeToString([]byte("short")))
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, uint32(len(payload)))
		conn.Write(header)
		conn.Write(payload)
		time.Sleep(100 * time.Millisecond)
	}()

	profile := tcp.NewTCPProfile("", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false)
	profile.CallbackUUID = "parent-uuid-1234"
	oldProfile := tcpProfileInstance
	tcpProfileInstance = profile
	defer func() { tcpProfileInstance = oldProfile }()

	cmd := &LinkCommand{}
	task := structs.Task{Params: `{"host": "127.0.0.1", "port": ` + itoa(port) + `}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Invalid checkin data") {
		t.Errorf("expected invalid checkin error, got: %s", result.Output)
	}
}

func TestLinkCommand_SuccessfulLink(t *testing.T) {
	// Mock child that sends a properly formatted checkin
	childUUID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	checkinBody := childUUID + "encrypted-body-data-here"
	checkinB64 := base64.StdEncoding.EncodeToString([]byte(checkinBody))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		payload := []byte(checkinB64)
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, uint32(len(payload)))
		conn.Write(header)
		conn.Write(payload)
		// Keep alive so readFromChild goroutine doesn't immediately error
		time.Sleep(500 * time.Millisecond)
	}()

	profile := tcp.NewTCPProfile("", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false)
	profile.CallbackUUID = "parent-uuid-1234"
	oldProfile := tcpProfileInstance
	tcpProfileInstance = profile
	defer func() { tcpProfileInstance = oldProfile }()

	cmd := &LinkCommand{}
	task := structs.Task{Params: `{"host": "127.0.0.1", "port": ` + itoa(port) + `}`}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success status, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Successfully linked") {
		t.Errorf("expected success message, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, childUUID[:8]) {
		t.Errorf("expected short UUID in output, got: %s", result.Output)
	}

	// Verify delegate message was sent
	select {
	case msg := <-profile.InboundDelegates:
		if msg.UUID != childUUID {
			t.Errorf("delegate UUID = %q, want %q", msg.UUID, childUUID)
		}
		if msg.C2ProfileName != "tcp" {
			t.Errorf("delegate profile = %q, want %q", msg.C2ProfileName, "tcp")
		}
	case <-time.After(time.Second):
		t.Error("no delegate message received")
	}

	// Verify edge message was sent
	select {
	case edge := <-profile.EdgeMessages:
		if edge.Action != "add" {
			t.Errorf("edge action = %q, want %q", edge.Action, "add")
		}
		if edge.Source != "parent-uuid-1234" {
			t.Errorf("edge source = %q, want %q", edge.Source, "parent-uuid-1234")
		}
		if edge.Destination != childUUID {
			t.Errorf("edge destination = %q, want %q", edge.Destination, childUUID)
		}
	case <-time.After(time.Second):
		t.Error("no edge message received")
	}

	// Verify child was registered
	uuids := profile.GetChildUUIDs()
	found := false
	for _, u := range uuids {
		if u == childUUID {
			found = true
		}
	}
	if !found {
		t.Errorf("child UUID %q not found in registered children", childUUID)
	}
}

func TestLinkCommand_ChildReadError(t *testing.T) {
	// Child that closes connection before sending data
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close() // Close immediately
	}()

	profile := tcp.NewTCPProfile("", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false)
	profile.CallbackUUID = "parent-uuid-1234"
	oldProfile := tcpProfileInstance
	tcpProfileInstance = profile
	defer func() { tcpProfileInstance = oldProfile }()

	cmd := &LinkCommand{}
	task := structs.Task{Params: `{"host": "127.0.0.1", "port": ` + itoa(port) + `}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Failed to read child checkin") {
		t.Errorf("expected read error, got: %s", result.Output)
	}
}

// =============================================================================
// UnlinkCommand tests
// =============================================================================

func TestUnlinkCommand_Name(t *testing.T) {
	cmd := &UnlinkCommand{}
	if cmd.Name() != "unlink" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "unlink")
	}
}

func TestUnlinkCommand_Description(t *testing.T) {
	cmd := &UnlinkCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestUnlinkCommand_InvalidJSON(t *testing.T) {
	cmd := &UnlinkCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Failed to parse") {
		t.Errorf("expected parse error, got: %s", result.Output)
	}
}

func TestUnlinkCommand_EmptyParams(t *testing.T) {
	cmd := &UnlinkCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "connection_id is required") {
		t.Errorf("expected connection_id required error, got: %s", result.Output)
	}
}

func TestUnlinkCommand_MissingConnectionID(t *testing.T) {
	cmd := &UnlinkCommand{}
	task := structs.Task{Params: `{}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "connection_id is required") {
		t.Errorf("expected connection_id required error, got: %s", result.Output)
	}
}

func TestUnlinkCommand_NoTCPProfile(t *testing.T) {
	oldProfile := tcpProfileInstance
	tcpProfileInstance = nil
	defer func() { tcpProfileInstance = oldProfile }()

	cmd := &UnlinkCommand{}
	task := structs.Task{Params: `{"connection_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "TCP P2P not available") {
		t.Errorf("expected TCP not available error, got: %s", result.Output)
	}
}

func TestUnlinkCommand_SuccessfulUnlink(t *testing.T) {
	childUUID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	profile := tcp.NewTCPProfile("", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false)
	profile.CallbackUUID = "parent-uuid-1234"

	// Add a mock child connection (use a pipe)
	server, client := net.Pipe()
	defer server.Close()

	// Manually add child without starting readFromChild goroutine
	// Use AddChildConnection (starts goroutine, but pipe will error immediately and exit)
	profile.AddChildConnection(childUUID, client)

	oldProfile := tcpProfileInstance
	tcpProfileInstance = profile
	defer func() { tcpProfileInstance = oldProfile }()

	cmd := &UnlinkCommand{}
	task := structs.Task{Params: `{"connection_id": "` + childUUID + `"}`}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success status, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Successfully unlinked") {
		t.Errorf("expected success message, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, childUUID[:8]) {
		t.Errorf("expected short UUID in output, got: %s", result.Output)
	}

	// Verify edge removal message
	select {
	case edge := <-profile.EdgeMessages:
		if edge.Action != "remove" {
			t.Errorf("edge action = %q, want %q", edge.Action, "remove")
		}
		if edge.Destination != childUUID {
			t.Errorf("edge destination = %q, want %q", edge.Destination, childUUID)
		}
	case <-time.After(time.Second):
		t.Error("no edge message received")
	}

	// Verify child was removed
	uuids := profile.GetChildUUIDs()
	for _, u := range uuids {
		if u == childUUID {
			t.Error("child should have been removed but was still found")
		}
	}
}

func TestUnlinkCommand_ShortUUID(t *testing.T) {
	profile := tcp.NewTCPProfile("", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false)
	profile.CallbackUUID = "parent-uuid-1234"

	oldProfile := tcpProfileInstance
	tcpProfileInstance = profile
	defer func() { tcpProfileInstance = oldProfile }()

	cmd := &UnlinkCommand{}
	// Short connection_id (< 8 chars)
	task := structs.Task{Params: `{"connection_id": "short"}`}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success status, got %q: %s", result.Status, result.Output)
	}
	// Should use full string since it's < 8 chars
	if !strings.Contains(result.Output, "short") {
		t.Errorf("expected short UUID in output, got: %s", result.Output)
	}

	// Drain the edge message
	<-profile.EdgeMessages
}

// =============================================================================
// SetTCPProfile / GetTCPProfile tests
// =============================================================================

func TestSetGetTCPProfile(t *testing.T) {
	oldProfile := tcpProfileInstance
	defer func() { tcpProfileInstance = oldProfile }()

	// Initially should be whatever it was before (may be nil)
	SetTCPProfile(nil)
	if GetTCPProfile() != nil {
		t.Error("expected nil after SetTCPProfile(nil)")
	}

	profile := tcp.NewTCPProfile("", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false)
	SetTCPProfile(profile)
	if GetTCPProfile() != profile {
		t.Error("GetTCPProfile didn't return the set profile")
	}
}

// itoa converts int to string without importing strconv
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}

// Ensure io import is used (for the recvTCPFramed test internals)
var _ = io.EOF
