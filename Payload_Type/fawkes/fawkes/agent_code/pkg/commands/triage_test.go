package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestTriageName(t *testing.T) {
	cmd := &TriageCommand{}
	if cmd.Name() != "triage" {
		t.Errorf("Expected 'triage', got '%s'", cmd.Name())
	}
}

func TestTriageDescription(t *testing.T) {
	cmd := &TriageCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestTriageBadJSON(t *testing.T) {
	cmd := &TriageCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("Expected error for bad JSON")
	}
}

func TestTriageUnknownAction(t *testing.T) {
	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for unknown action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("Expected unknown action error, got: %s", result.Output)
	}
}

func TestTriageCustomMissingPath(t *testing.T) {
	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "custom"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for custom without path")
	}
	if !strings.Contains(result.Output, "-path required") {
		t.Errorf("Expected path required error, got: %s", result.Output)
	}
}

func TestTriageCustom(t *testing.T) {
	tmpDir := t.TempDir()
	// Create some files
	os.WriteFile(filepath.Join(tmpDir, "report.txt"), []byte("data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "notes.md"), []byte("notes"), 0644)

	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "custom", Path: tmpDir})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "FILE TRIAGE") {
		t.Errorf("Expected FILE TRIAGE header, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "2 files found") {
		t.Errorf("Expected 2 files found, got: %s", result.Output)
	}
}

func TestTriageCustomMaxFiles(t *testing.T) {
	tmpDir := t.TempDir()
	for i := 0; i < 10; i++ {
		os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i)), []byte("data"), 0644)
	}

	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "custom", Path: tmpDir, MaxFiles: 3})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "3 files found") {
		t.Errorf("Expected 3 files found (max), got: %s", result.Output)
	}
}

func TestTriageCustomSkipsEmptyFiles(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "empty.txt"), []byte{}, 0644)
	os.WriteFile(filepath.Join(tmpDir, "notempty.txt"), []byte("content"), 0644)

	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "custom", Path: tmpDir})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	// Only notempty.txt should be found (empty is skipped)
	if !strings.Contains(result.Output, "1 files found") {
		t.Errorf("Expected 1 file (empty skipped), got: %s", result.Output)
	}
}

func TestTriageCustomMaxSize(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "small.txt"), []byte("small"), 0644)
	// Create a file larger than 100 bytes
	bigData := make([]byte, 200)
	os.WriteFile(filepath.Join(tmpDir, "big.txt"), bigData, 0644)

	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "custom", Path: tmpDir, MaxSize: 100})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "1 files found") {
		t.Errorf("Expected 1 file (big skipped), got: %s", result.Output)
	}
}

func TestTriageDefaultAction(t *testing.T) {
	// Default action is "all" — should not error
	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success for default action, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "FILE TRIAGE") {
		t.Errorf("Expected FILE TRIAGE header, got: %s", result.Output)
	}
}

func TestTriageDocuments(t *testing.T) {
	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "documents"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success for documents, got %s: %s", result.Status, result.Output)
	}
}

func TestTriageCredentials(t *testing.T) {
	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "credentials"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success for credentials, got %s: %s", result.Status, result.Output)
	}
}

func TestTriageConfigs(t *testing.T) {
	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "configs"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success for configs, got %s: %s", result.Status, result.Output)
	}
}

func TestTriageCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	for i := 0; i < 50; i++ {
		os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i)), []byte("data"), 0644)
	}

	task := structs.NewTask("triage-cancel", "triage", "")
	task.SetStop() // Immediately cancel

	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "custom", Path: tmpDir})
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success on cancel, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "cancelled") {
		t.Errorf("Expected cancelled message, got: %s", result.Output)
	}
}

func TestFormatTriageSize(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0B"},
		{512, "512B"},
		{1024, "1.0KB"},
		{1536, "1.5KB"},
		{1048576, "1.0MB"},
		{5242880, "5.0MB"},
	}

	for _, tc := range tests {
		result := formatTriageSize(tc.bytes)
		if result != tc.expected {
			t.Errorf("formatTriageSize(%d) = %s, want %s", tc.bytes, result, tc.expected)
		}
	}
}

func TestTriageScan(t *testing.T) {
	tmpDir := t.TempDir()
	// Create files with different extensions
	os.WriteFile(filepath.Join(tmpDir, "report.pdf"), []byte("pdf"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "data.xlsx"), []byte("excel"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "app.exe"), []byte("binary"), 0644)

	task := structs.NewTask("scan-test", "triage", "")
	args := triageArgs{MaxSize: 10 * 1024 * 1024, MaxFiles: 200}

	results := triageScan(task, []string{tmpDir}, []string{".pdf", ".xlsx"}, "doc", args, 3)
	if len(results) != 2 {
		t.Errorf("Expected 2 results (pdf+xlsx), got %d", len(results))
	}
	for _, r := range results {
		if r.Category != "doc" {
			t.Errorf("Expected category 'doc', got '%s'", r.Category)
		}
	}
}

func TestTriageScanPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "id_rsa"), []byte("key"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "test.kdbx"), []byte("keepass"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "normal.txt"), []byte("text"), 0644)

	task := structs.NewTask("pattern-test", "triage", "")
	args := triageArgs{MaxSize: 10 * 1024 * 1024, MaxFiles: 200}

	results := triageScanPatterns(task, []string{tmpDir}, []string{"id_rsa", "*.kdbx"}, "cred", args, 3)
	if len(results) != 2 {
		t.Errorf("Expected 2 results (id_rsa+kdbx), got %d", len(results))
	}
}
