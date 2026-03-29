//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestRegCommandName(t *testing.T) {
	assertCommandName(t, &RegCommand{}, "reg")
}

func TestRegCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &RegCommand{})
}

func TestRegEmptyParams(t *testing.T) {
	cmd := &RegCommand{}
	result := cmd.Execute(mockTask("reg", ""))
	// Empty params should show usage, not error
	assertSuccess(t, result)
	assertOutputContains(t, result, "Usage")
}

func TestRegInvalidJSON(t *testing.T) {
	cmd := &RegCommand{}
	result := cmd.Execute(mockTask("reg", "not json"))
	assertError(t, result)
}

func TestRegUnknownAction(t *testing.T) {
	cmd := &RegCommand{}
	params, _ := json.Marshal(regArgs{Action: "invalid"})
	result := cmd.Execute(mockTask("reg", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "Unknown action")
}

func TestRegReadMissingPath(t *testing.T) {
	cmd := &RegCommand{}
	params, _ := json.Marshal(regArgs{Action: "read"})
	result := cmd.Execute(mockTask("reg", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "path is required")
}

func TestRegWriteMissingPath(t *testing.T) {
	cmd := &RegCommand{}
	params, _ := json.Marshal(regArgs{Action: "write"})
	result := cmd.Execute(mockTask("reg", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "path is required")
}

func TestRegSearchMissingPattern(t *testing.T) {
	cmd := &RegCommand{}
	params, _ := json.Marshal(regArgs{Action: "search"})
	result := cmd.Execute(mockTask("reg", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "pattern is required")
}

func TestRegArgsUnmarshal(t *testing.T) {
	var args regArgs
	data := `{"action":"read","hive":"HKLM","path":"SOFTWARE\\Microsoft","name":"test","recursive":"true","max_depth":3,"max_results":10}`
	if err := json.Unmarshal([]byte(data), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.Action != "read" {
		t.Errorf("Action = %q, want read", args.Action)
	}
	if args.Hive != "HKLM" {
		t.Errorf("Hive = %q, want HKLM", args.Hive)
	}
	if args.Path != "SOFTWARE\\Microsoft" {
		t.Errorf("Path = %q, want SOFTWARE\\Microsoft", args.Path)
	}
	if args.MaxDepth != 3 {
		t.Errorf("MaxDepth = %d, want 3", args.MaxDepth)
	}
}

func TestRegReadValidKey(t *testing.T) {
	cmd := &RegCommand{}
	params, _ := json.Marshal(regArgs{
		Action: "read",
		Hive:   "HKLM",
		Path:   "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
	})
	result := cmd.Execute(mockTask("reg", string(params)))
	assertSuccess(t, result)
}

func TestRegReadSpecificValue(t *testing.T) {
	cmd := &RegCommand{}
	params, _ := json.Marshal(regArgs{
		Action: "read",
		Hive:   "HKLM",
		Path:   "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
		Name:   "ProductName",
	})
	result := cmd.Execute(mockTask("reg", string(params)))
	assertSuccess(t, result)
	assertOutputContains(t, result, "Windows")
}

func TestRegReadInvalidHive(t *testing.T) {
	cmd := &RegCommand{}
	params, _ := json.Marshal(regArgs{
		Action: "read",
		Hive:   "INVALID",
		Path:   "SOFTWARE",
	})
	result := cmd.Execute(mockTask("reg", string(params)))
	assertError(t, result)
}

func TestRegSearchRunsOnValidKey(t *testing.T) {
	cmd := &RegCommand{}
	params, _ := json.Marshal(regArgs{
		Action:     "search",
		Hive:       "HKLM",
		Path:       "SOFTWARE\\Microsoft",
		Pattern:    "Windows",
		MaxDepth:   1,
		MaxResults: 5,
	})
	result := cmd.Execute(mockTask("reg", string(params)))
	assertSuccess(t, result)
}
