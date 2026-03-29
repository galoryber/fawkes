//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestBitsCommandName(t *testing.T) {
	assertCommandName(t, &BitsCommand{}, "bits")
}

func TestBitsCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &BitsCommand{})
}

func TestBitsEmptyParamsDefaultsList(t *testing.T) {
	cmd := &BitsCommand{}
	// Empty params should default to "list" action
	result := cmd.Execute(mockTask("bits", ""))
	// Will attempt COM — may error in test environment but shouldn't panic
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status: %q", result.Status)
	}
}

func TestBitsInvalidJSON(t *testing.T) {
	cmd := &BitsCommand{}
	result := cmd.Execute(mockTask("bits", "not json"))
	assertError(t, result)
}

func TestBitsUnknownAction(t *testing.T) {
	cmd := &BitsCommand{}
	params, _ := json.Marshal(bitsArgs{Action: "badaction"})
	result := cmd.Execute(mockTask("bits", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "Unknown action")
}

func TestBitsCreateMissingParams(t *testing.T) {
	cmd := &BitsCommand{}

	// Missing name
	params, _ := json.Marshal(bitsArgs{Action: "create", URL: "http://example.com", Path: "C:\\out.txt"})
	result := cmd.Execute(mockTask("bits", string(params)))
	assertError(t, result)

	// Missing URL
	params, _ = json.Marshal(bitsArgs{Action: "create", Name: "test", Path: "C:\\out.txt"})
	result = cmd.Execute(mockTask("bits", string(params)))
	assertError(t, result)

	// Missing path
	params, _ = json.Marshal(bitsArgs{Action: "create", Name: "test", URL: "http://example.com"})
	result = cmd.Execute(mockTask("bits", string(params)))
	assertError(t, result)
}

func TestBitsPersistMissingParams(t *testing.T) {
	cmd := &BitsCommand{}

	// Missing command
	params, _ := json.Marshal(bitsArgs{Action: "persist", Name: "test", URL: "http://example.com", Path: "C:\\out.txt"})
	result := cmd.Execute(mockTask("bits", string(params)))
	assertError(t, result)
}

func TestBitsCancelMissingName(t *testing.T) {
	cmd := &BitsCommand{}
	params, _ := json.Marshal(bitsArgs{Action: "cancel"})
	result := cmd.Execute(mockTask("bits", string(params)))
	assertError(t, result)
}

func TestBitsSuspendMissingName(t *testing.T) {
	cmd := &BitsCommand{}
	params, _ := json.Marshal(bitsArgs{Action: "suspend"})
	result := cmd.Execute(mockTask("bits", string(params)))
	assertError(t, result)
}

func TestBitsResumeMissingName(t *testing.T) {
	cmd := &BitsCommand{}
	params, _ := json.Marshal(bitsArgs{Action: "resume"})
	result := cmd.Execute(mockTask("bits", string(params)))
	assertError(t, result)
}

func TestBitsCompleteMissingName(t *testing.T) {
	cmd := &BitsCommand{}
	params, _ := json.Marshal(bitsArgs{Action: "complete"})
	result := cmd.Execute(mockTask("bits", string(params)))
	assertError(t, result)
}

func TestBitsArgsUnmarshal(t *testing.T) {
	var args bitsArgs
	data := `{"action":"create","name":"test","url":"http://example.com","path":"C:\\out.txt","command":"calc.exe","cmd_args":"/c"}`
	if err := json.Unmarshal([]byte(data), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.Action != "create" {
		t.Errorf("expected action=create, got %q", args.Action)
	}
	if args.Name != "test" {
		t.Errorf("expected name=test, got %q", args.Name)
	}
	if args.Command != "calc.exe" {
		t.Errorf("expected command=calc.exe, got %q", args.Command)
	}
}
