//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestHandlesCommandName(t *testing.T) {
	assertCommandName(t, &HandlesCommand{}, "handles")
}

func TestHandlesCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &HandlesCommand{})
}

func TestHandlesEmptyParams(t *testing.T) {
	cmd := &HandlesCommand{}
	result := cmd.Execute(mockTask("handles", ""))
	assertError(t, result)
}

func TestHandlesInvalidJSON(t *testing.T) {
	cmd := &HandlesCommand{}
	result := cmd.Execute(mockTask("handles", "not json"))
	assertError(t, result)
}

func TestHandlesMissingPID(t *testing.T) {
	cmd := &HandlesCommand{}
	params, _ := json.Marshal(handlesArgs{PID: 0})
	result := cmd.Execute(mockTask("handles", string(params)))
	assertError(t, result)
}

func TestHandlesNegativePID(t *testing.T) {
	cmd := &HandlesCommand{}
	params, _ := json.Marshal(handlesArgs{PID: -1})
	result := cmd.Execute(mockTask("handles", string(params)))
	assertError(t, result)
}

func TestHandlesArgsUnmarshal(t *testing.T) {
	var args handlesArgs
	data := `{"pid":1234,"type":"File","max_count":100,"show_names":true}`
	if err := json.Unmarshal([]byte(data), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.PID != 1234 {
		t.Errorf("expected PID=1234, got %d", args.PID)
	}
	if args.TypeName != "File" {
		t.Errorf("expected type=File, got %q", args.TypeName)
	}
	if args.MaxCount != 100 {
		t.Errorf("expected max_count=100, got %d", args.MaxCount)
	}
	if !args.ShowNames {
		t.Error("expected show_names=true")
	}
}

func TestHandlesFormatResult(t *testing.T) {
	handles := []handleInfo{
		{Handle: 1, TypeName: "File", Name: "test.txt"},
		{Handle: 2, TypeName: "Key", Name: "HKLM\\Software"},
	}
	typeCounts := map[string]int{"File": 1, "Key": 1}
	args := handlesArgs{PID: 1234, MaxCount: 500}

	result := formatHandleResult(handles, typeCounts, args, 2)
	assertSuccess(t, result)
	assertOutputContains(t, result, "1234")
	assertOutputContains(t, result, "File")
}

func TestHandlesNTConstants(t *testing.T) {
	if systemHandleInformation != 16 {
		t.Errorf("systemHandleInformation = %d, want 16", systemHandleInformation)
	}
	if statusInfoLengthMismatch != 0xC0000004 {
		t.Errorf("statusInfoLengthMismatch = 0x%X, want 0xC0000004", statusInfoLengthMismatch)
	}
}
