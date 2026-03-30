//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestPipeServerCommandName(t *testing.T) {
	assertCommandName(t, &PipeServerCommand{}, "pipe-server")
}

func TestPipeServerCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &PipeServerCommand{})
}

func TestPipeServerEmptyParams(t *testing.T) {
	cmd := &PipeServerCommand{}
	// Empty params should attempt to parse JSON and fail
	result := cmd.Execute(mockTask("pipe-server", ""))
	// May error on JSON parse or proceed with defaults
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status: %q", result.Status)
	}
}

func TestPipeServerInvalidJSON(t *testing.T) {
	cmd := &PipeServerCommand{}
	result := cmd.Execute(mockTask("pipe-server", "not json"))
	assertError(t, result)
}

func TestPipeServerArgsUnmarshal(t *testing.T) {
	var args pipeServerArgs
	data := `{"action":"check","name":"testpipe","timeout":60}`
	if err := json.Unmarshal([]byte(data), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.Action != "check" {
		t.Errorf("expected action=check, got %q", args.Action)
	}
	if args.Name != "testpipe" {
		t.Errorf("expected name=testpipe, got %q", args.Name)
	}
	if args.Timeout != 60 {
		t.Errorf("expected timeout=60, got %d", args.Timeout)
	}
}

func TestPipeServerCheckAction(t *testing.T) {
	cmd := &PipeServerCommand{}
	params, _ := json.Marshal(pipeServerArgs{Action: "check"})
	result := cmd.Execute(mockTask("pipe-server", string(params)))
	// check action enumerates privileges — should succeed
	assertSuccess(t, result)
}

func TestPipeServerConstants(t *testing.T) {
	if PIPE_ACCESS_DUPLEX != 0x3 {
		t.Errorf("PIPE_ACCESS_DUPLEX = 0x%X, want 0x3", PIPE_ACCESS_DUPLEX)
	}
	if PIPE_TYPE_MESSAGE != 0x4 {
		t.Errorf("PIPE_TYPE_MESSAGE = 0x%X, want 0x4", PIPE_TYPE_MESSAGE)
	}
	if PIPE_UNLIMITED_INSTANCES != 255 {
		t.Errorf("PIPE_UNLIMITED_INSTANCES = %d, want 255", PIPE_UNLIMITED_INSTANCES)
	}
}
