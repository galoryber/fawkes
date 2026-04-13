package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSmbTaint_MissingSourceAndContent(t *testing.T) {
	cmd := &SmbCommand{}
	params, _ := json.Marshal(smbArgs{
		Action:   "taint",
		Host:     "127.0.0.1",
		Username: "user",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for taint without source/content, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "source") {
		t.Errorf("expected error about source, got: %s", result.Output)
	}
}

func TestSmbTaint_EmptySourceFile(t *testing.T) {
	// Create an empty temp file
	tmpFile, err := os.CreateTemp("", "smb_taint_test_*")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	cmd := &SmbCommand{}
	params, _ := json.Marshal(smbArgs{
		Action:   "taint",
		Host:     "127.0.0.1",
		Username: "user",
		Password: "pass",
		Source:   tmpFile.Name(),
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for empty source file, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "empty") {
		t.Errorf("expected empty file error, got: %s", result.Output)
	}
}

func TestSmbTaint_NonexistentSourceFile(t *testing.T) {
	cmd := &SmbCommand{}
	params, _ := json.Marshal(smbArgs{
		Action:   "taint",
		Host:     "127.0.0.1",
		Username: "user",
		Password: "pass",
		Source:   "/nonexistent/file.exe",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent source, got %q", result.Status)
	}
}

func TestSmbTaint_ContentMode(t *testing.T) {
	// Content mode should fail on network, not on validation
	cmd := &SmbCommand{}
	params, _ := json.Marshal(smbArgs{
		Action:   "taint",
		Host:     "127.0.0.1",
		Username: "user",
		Password: "pass",
		Content:  "malicious content here",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should fail on SMB connect, not on validation
	if result.Status != "error" {
		t.Errorf("expected error (network), got %q", result.Status)
	}
	if strings.Contains(result.Output, "source") && strings.Contains(result.Output, "required") {
		t.Error("content should be accepted as alternative to source")
	}
}

func TestSmbTaint_PlantNameFromSource(t *testing.T) {
	// Create a temp file with some content
	tmpDir, err := os.MkdirTemp("", "smb_taint_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "payload.exe")
	if err := os.WriteFile(testFile, []byte("test payload data"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := &SmbCommand{}
	params, _ := json.Marshal(smbArgs{
		Action:   "taint",
		Host:     "127.0.0.1",
		Username: "user",
		Password: "pass",
		Source:   testFile,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Will fail on SMB connect — verify it got past validation
	if result.Status != "error" {
		t.Errorf("expected network error, got %q", result.Status)
	}
	// Should fail on connection, not on validation
	if strings.Contains(result.Output, "required") || strings.Contains(result.Output, "empty") {
		t.Errorf("should pass validation with valid source file, got: %s", result.Output)
	}
}

func TestSmbTaint_PlantNameDefault(t *testing.T) {
	cmd := &SmbCommand{}
	params, _ := json.Marshal(smbArgs{
		Action:   "taint",
		Host:     "127.0.0.1",
		Username: "user",
		Password: "pass",
		Content:  "data",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Content mode with no source or plant_name — default "desktop.ini" used
	// Will fail on SMB connect
	if strings.Contains(result.Output, "required") || strings.Contains(result.Output, "empty") {
		t.Errorf("should pass validation with content, got: %s", result.Output)
	}
}

func TestIsPermissionError(t *testing.T) {
	tests := []struct {
		name     string
		errStr   string
		expected bool
	}{
		{"nil-like empty", "", false},
		{"access denied", "Access is denied", true},
		{"permission denied", "permission denied", true},
		{"STATUS_ACCESS_DENIED", "STATUS_ACCESS_DENIED", true},
		{"lowercase access denied", "access denied", true},
		{"random error", "connection refused", false},
		{"timeout", "i/o timeout", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.errStr == "" {
				if isPermissionError(nil) {
					t.Error("nil error should not be permission error")
				}
				return
			}
			err := &testError{msg: tt.errStr}
			got := isPermissionError(err)
			if got != tt.expected {
				t.Errorf("isPermissionError(%q) = %v, want %v", tt.errStr, got, tt.expected)
			}
		})
	}
}

// testError is a simple error implementation for testing.
type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

func TestSmbTaintResult_JSONStructure(t *testing.T) {
	result := smbTaintResult{
		Action:       "taint",
		Host:         "192.168.1.100",
		PlantName:    "update.exe",
		SharesTested: 5,
		Planted: []smbPlantedFile{
			{Share: "Users", Path: "update.exe", Size: 1024, Timestomped: true, StompSource: "readme.txt"},
			{Share: "Public", Path: "update.exe", Size: 1024, Timestomped: false},
		},
		Skipped: []smbSkippedShare{
			{Share: "IPC$", Reason: "IPC$ is not a file share"},
			{Share: "ADMIN$", Reason: "write access denied"},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal taint result: %v", err)
	}

	// Verify round-trip
	var parsed smbTaintResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal taint result: %v", err)
	}

	if parsed.Action != "taint" {
		t.Errorf("action: got %q, want %q", parsed.Action, "taint")
	}
	if parsed.Host != "192.168.1.100" {
		t.Errorf("host: got %q, want %q", parsed.Host, "192.168.1.100")
	}
	if len(parsed.Planted) != 2 {
		t.Errorf("planted count: got %d, want 2", len(parsed.Planted))
	}
	if len(parsed.Skipped) != 2 {
		t.Errorf("skipped count: got %d, want 2", len(parsed.Skipped))
	}
	if !parsed.Planted[0].Timestomped {
		t.Error("first planted file should be timestomped")
	}
	if parsed.Planted[0].StompSource != "readme.txt" {
		t.Errorf("stomp source: got %q, want %q", parsed.Planted[0].StompSource, "readme.txt")
	}
	if parsed.Planted[1].Timestomped {
		t.Error("second planted file should not be timestomped")
	}
}

func TestSmbStompResult_Fields(t *testing.T) {
	r := smbStompResult{success: true, sourceFile: "existing.dll"}
	if !r.success {
		t.Error("expected success")
	}
	if r.sourceFile != "existing.dll" {
		t.Errorf("sourceFile: got %q, want %q", r.sourceFile, "existing.dll")
	}

	r2 := smbStompResult{success: false}
	if r2.success {
		t.Error("expected failure")
	}
	if r2.sourceFile != "" {
		t.Errorf("sourceFile should be empty, got %q", r2.sourceFile)
	}
}
