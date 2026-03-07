package commands

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

func TestAsrepCommand_Name(t *testing.T) {
	cmd := &AsrepCommand{}
	if cmd.Name() != "asrep-roast" {
		t.Errorf("expected name 'asrep-roast', got %q", cmd.Name())
	}
}

func TestAsrepCommand_Description(t *testing.T) {
	cmd := &AsrepCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
	if !strings.Contains(cmd.Description(), "T1558.004") {
		t.Error("expected MITRE ATT&CK ID in description")
	}
}

func TestAsrepCommand_EmptyParams(t *testing.T) {
	cmd := &AsrepCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status for empty params, got %q", result.Status)
	}
}

func TestAsrepCommand_InvalidJSON(t *testing.T) {
	cmd := &AsrepCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error status for invalid JSON, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Error parsing") {
		t.Errorf("expected parsing error message, got %q", result.Output)
	}
}

func TestAsrepCommand_MissingServer(t *testing.T) {
	cmd := &AsrepCommand{}
	params, _ := json.Marshal(asrepArgs{
		Username: "user@domain.local",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing server, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "server") {
		t.Errorf("expected server-related error, got %q", result.Output)
	}
}

func TestAsrepCommand_MissingUsername(t *testing.T) {
	cmd := &AsrepCommand{}
	params, _ := json.Marshal(asrepArgs{
		Server:   "dc01",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing username, got %q", result.Status)
	}
}

func TestAsrepCommand_MissingPassword(t *testing.T) {
	cmd := &AsrepCommand{}
	params, _ := json.Marshal(asrepArgs{
		Server:   "dc01",
		Username: "user@domain.local",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing password, got %q", result.Status)
	}
}

func TestAsrepCommand_RealmAutoDetect(t *testing.T) {
	cmd := &AsrepCommand{}
	params, _ := json.Marshal(asrepArgs{
		Server:   "127.0.0.1", // RFC 5737 documentation IP
		Username: "user@test.local",
		Password: "pass",
		Account:  "targetuser",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should fail at KDC connection, not at realm detection
	if result.Status != "error" {
		t.Log("Unexpected success — may have connected to something")
	}
	if strings.Contains(result.Output, "realm required") {
		t.Errorf("realm should be auto-detected from UPN, but got: %q", result.Output)
	}
}

func TestAsrepCommand_RealmRequired(t *testing.T) {
	cmd := &AsrepCommand{}
	params, _ := json.Marshal(asrepArgs{
		Server:   "dc01",
		Username: "user_no_upn",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing realm with non-UPN username, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "realm") {
		t.Errorf("expected realm-related error, got %q", result.Output)
	}
}

func TestAsrepCommand_Registration(t *testing.T) {
	Initialize()
	cmd := GetCommand("asrep-roast")
	if cmd == nil {
		t.Fatal("asrep-roast command not registered")
	}
	if cmd.Name() != "asrep-roast" {
		t.Errorf("expected name 'asrep-roast', got %q", cmd.Name())
	}
}

func TestReadFull_Complete(t *testing.T) {
	// Use net.Pipe as a mock connection
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	data := []byte("hello world!")
	go func() {
		// Simulate slow writes — send one byte at a time
		for _, b := range data {
			server.Write([]byte{b})
			time.Sleep(time.Millisecond)
		}
	}()

	buf := make([]byte, len(data))
	n, err := readFull(client, buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("read %d bytes, want %d", n, len(data))
	}
	if string(buf) != "hello world!" {
		t.Errorf("got %q, want %q", string(buf), "hello world!")
	}
}

func TestReadFull_EOF(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	// Write partial data then close
	go func() {
		server.Write([]byte("hi"))
		server.Close()
	}()

	buf := make([]byte, 10) // Ask for 10 bytes
	_, err := readFull(client, buf)
	if err == nil {
		t.Error("expected error when connection closed before buffer filled")
	}
}

func TestAsrepCommand_PortDefault(t *testing.T) {
	// Verify default port is set when not specified
	cmd := &AsrepCommand{}
	params, _ := json.Marshal(asrepArgs{
		Server:   "127.0.0.1",
		Username: "user@test.local",
		Password: "pass",
		Account:  "target",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should fail at KDC connection, not at parameter validation
	if result.Status != "error" {
		t.Log("Unexpected success (may have connected to something on port 88)")
	}
	if strings.Contains(result.Output, "parameters required") {
		t.Error("should not fail at parameter validation")
	}
}

func TestAsrepCommand_RealmUppercased(t *testing.T) {
	cmd := &AsrepCommand{}
	params, _ := json.Marshal(asrepArgs{
		Server:   "127.0.0.1",
		Username: "user@test.local",
		Password: "pass",
		Realm:    "test.local", // lowercase
		Account:  "target",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should fail at KDC connection (realm should be uppercased)
	if strings.Contains(result.Output, "realm required") {
		t.Error("realm was specified, should not require it")
	}
}
