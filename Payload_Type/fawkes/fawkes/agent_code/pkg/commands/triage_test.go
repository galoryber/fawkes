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
	var results []triageResult
	if err := json.Unmarshal([]byte(result.Output), &results); err != nil {
		t.Fatalf("Expected valid JSON array, got parse error: %v\nOutput: %s", err, result.Output)
	}
	if len(results) != 2 {
		t.Errorf("Expected 2 files in JSON array, got %d", len(results))
	}
	for _, r := range results {
		if r.Category != "custom" {
			t.Errorf("Expected category 'custom', got '%s'", r.Category)
		}
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
	var results []triageResult
	if err := json.Unmarshal([]byte(result.Output), &results); err != nil {
		t.Fatalf("Expected valid JSON array, got parse error: %v\nOutput: %s", err, result.Output)
	}
	if len(results) != 3 {
		t.Errorf("Expected 3 files (max), got %d", len(results))
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
	var results []triageResult
	if err := json.Unmarshal([]byte(result.Output), &results); err != nil {
		t.Fatalf("Expected valid JSON array, got parse error: %v\nOutput: %s", err, result.Output)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 file (empty skipped), got %d", len(results))
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
	var results []triageResult
	if err := json.Unmarshal([]byte(result.Output), &results); err != nil {
		t.Fatalf("Expected valid JSON array, got parse error: %v\nOutput: %s", err, result.Output)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 file (big skipped), got %d", len(results))
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
	// Output should be valid JSON (either [] or an array of triageResult)
	var results []triageResult
	if err := json.Unmarshal([]byte(result.Output), &results); err != nil {
		t.Errorf("Expected valid JSON array output, got parse error: %v\nOutput: %s", err, result.Output)
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

// --- triageCategorizeFile tests ---

func TestTriageCategorizeFile(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		// Credentials
		{"id_rsa", "cred"},
		{"id_ed25519", "cred"},
		{"server.pem", "cred"},
		{"cert.pfx", "cred"},
		{"backup.kdbx", "cred"},
		{"user.rdp", "cred"},
		{"client.ovpn", "cred"},
		{".netrc", "cred"},
		{"credentials.json", "cred"},

		// Documents
		{"report.docx", "doc"},
		{"budget.xlsx", "doc"},
		{"slides.pptx", "doc"},
		{"manual.pdf", "doc"},
		{"data.csv", "doc"},

		// Configs
		{"app.yaml", "config"},
		{"settings.json", "config"},
		{"config.toml", "config"},
		{"nginx.conf", "config"},
		{".env", "config"},
		{"app.ini", "config"},

		// Scripts
		{"deploy.sh", "script"},
		{"setup.py", "script"},
		{"build.ps1", "script"},
		{"run.bat", "script"},

		// Logs
		{"auth.log", "log"},
		{"app.log", "log"},
		{"syslog", "log"},

		// Databases
		{"app.db", "database"},
		{"data.sqlite", "database"},
		{"history.sqlite3", "database"},

		// Other
		{"photo.jpg", "other"},
		{"program.exe", "other"},
		{"archive.tar.gz", "other"},
	}

	for _, tc := range tests {
		got := triageCategorizeFile(tc.name)
		if got != tc.expected {
			t.Errorf("triageCategorizeFile(%q) = %q, want %q", tc.name, got, tc.expected)
		}
	}
}

func TestTriageRecent(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a recently modified file
	os.WriteFile(filepath.Join(tmpDir, "recent.txt"), []byte("recent data"), 0644)

	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "recent", Hours: 1, Path: tmpDir})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success for recent, got %s: %s", result.Status, result.Output)
	}
}

func TestTriageRecentDefaultHours(t *testing.T) {
	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "recent"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success for recent (default hours), got %s: %s", result.Status, result.Output)
	}
}

func TestTriageRecentStringHours(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "recent.txt"), []byte("data"), 0644)

	cmd := &TriageCommand{}
	// Mythic UI or manual JSON may send hours as string
	result := cmd.Execute(structs.Task{Params: `{"action":"recent","hours":"2","path":"` + tmpDir + `"}`})
	if result.Status != "success" {
		t.Errorf("Expected success for string hours, got %s: %s", result.Status, result.Output)
	}
}

func TestFlexIntUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		wantErr  bool
	}{
		{"integer", `42`, 42, false},
		{"string_int", `"24"`, 24, false},
		{"zero", `0`, 0, false},
		{"string_zero", `"0"`, 0, false},
		{"negative", `-1`, -1, false},
		{"invalid_string", `"abc"`, 0, true},
		{"null_value", `null`, 0, false}, // null → zero (Go default)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v flexInt
			err := json.Unmarshal([]byte(tt.input), &v)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %s", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if int(v) != tt.expected {
				t.Errorf("got %d, want %d", int(v), tt.expected)
			}
		})
	}
}

func TestTriageDatabase(t *testing.T) {
	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "database", MaxFiles: 10})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestTriageScripts(t *testing.T) {
	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "scripts", MaxFiles: 10})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestTriageArchives(t *testing.T) {
	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "archives", MaxFiles: 10})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestTriageDatabaseFindsFiles(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "app.db"), []byte("SQLite format"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "data.sqlite3"), []byte("data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("text"), 0644)

	task := structs.NewTask("db-test", "triage", "")
	args := triageArgs{MaxSize: 10 * 1024 * 1024, MaxFiles: 200}
	results := triageScan(task, []string{tmpDir}, []string{".db", ".sqlite3"}, "database", args, 3)

	if len(results) != 2 {
		names := make([]string, len(results))
		for i, r := range results {
			names[i] = r.Path
		}
		t.Errorf("expected 2 database files, got %d: %v", len(results), names)
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

func TestTriageMail(t *testing.T) {
	cmd := &TriageCommand{}
	params, _ := json.Marshal(triageArgs{Action: "mail"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for mail triage, got %q: %s", result.Status, result.Output)
	}
}

func TestTriageMailFindsFiles(t *testing.T) {
	tmpDir := t.TempDir()
	// Create mock mail files
	os.WriteFile(filepath.Join(tmpDir, "inbox.pst"), []byte("PST data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "message.eml"), []byte("From: test"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "archive.mbox"), []byte("mbox data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "not_mail.txt"), []byte("text"), 0644)

	task := structs.NewTask("mail-test", "triage", "")
	args := triageArgs{MaxSize: 10 * 1024 * 1024, MaxFiles: 200}
	exts := []string{".pst", ".ost", ".eml", ".msg", ".mbox", ".emlx", ".dbx", ".nsf"}
	results := triageScan(task, []string{tmpDir}, exts, "mail", args, 3)
	if len(results) != 3 {
		t.Errorf("expected 3 mail files, got %d", len(results))
	}
	for _, r := range results {
		if r.Category != "mail" {
			t.Errorf("expected category 'mail', got %q for %s", r.Category, r.Path)
		}
	}
}

func TestTriageCategorizeFileMail(t *testing.T) {
	mailTests := []struct {
		name     string
		expected string
	}{
		{"inbox.pst", "mail"},
		{"outlook.ost", "mail"},
		{"message.eml", "mail"},
		{"report.msg", "mail"},
		{"archive.mbox", "mail"},
		{"old.emlx", "mail"},
		{"legacy.dbx", "mail"},
		{"notes.nsf", "mail"},
	}
	for _, tc := range mailTests {
		got := triageCategorizeFile(tc.name)
		if got != tc.expected {
			t.Errorf("triageCategorizeFile(%q) = %q, want %q", tc.name, got, tc.expected)
		}
	}
}
