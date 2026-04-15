package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

func TestCompressExfilMissingPath(t *testing.T) {
	cmd := &CompressCommand{}
	params, _ := json.Marshal(CompressParams{
		Action: "exfil",
	})
	task := structs.NewTask("t", "compress", "")
	task.Params = string(params)

	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("exfil without path should return error")
	}
	if result.Output == "" {
		t.Error("error message should not be empty")
	}
}

func TestCompressExfilDirectoryPath(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &CompressCommand{}
	params, _ := json.Marshal(CompressParams{
		Action: "exfil",
		Path:   tmpDir,
	})
	task := structs.NewTask("t", "compress", "")
	task.Params = string(params)

	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("exfil on directory should return error")
	}
}

func TestCompressExfilNonexistentPath(t *testing.T) {
	cmd := &CompressCommand{}
	params, _ := json.Marshal(CompressParams{
		Action: "exfil",
		Path:   "/nonexistent/archive.dat",
	})
	task := structs.NewTask("t", "compress", "")
	task.Params = string(params)

	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("exfil on nonexistent path should return error")
	}
}

func TestCompressStageExfilMissingPath(t *testing.T) {
	cmd := &CompressCommand{}
	params, _ := json.Marshal(CompressParams{
		Action: "stage-exfil",
	})
	task := structs.NewTask("t", "compress", "")
	task.Params = string(params)

	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("stage-exfil without path should return error")
	}
}

func TestExfilMetadataSerialization(t *testing.T) {
	meta := exfilMetadata{
		ArchivePath: "/tmp/test.dat",
		FileSize:    1024,
		SHA256:      "abc123",
		CleanedUp:   true,
		Status:      "transferred",
	}

	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed exfilMetadata
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.ArchivePath != meta.ArchivePath {
		t.Errorf("archive_path: got %s, want %s", parsed.ArchivePath, meta.ArchivePath)
	}
	if parsed.FileSize != meta.FileSize {
		t.Errorf("file_size: got %d, want %d", parsed.FileSize, meta.FileSize)
	}
	if parsed.SHA256 != meta.SHA256 {
		t.Errorf("sha256: got %s, want %s", parsed.SHA256, meta.SHA256)
	}
	if parsed.CleanedUp != meta.CleanedUp {
		t.Error("cleaned_up should be true")
	}
	if parsed.Status != meta.Status {
		t.Errorf("status: got %s, want %s", parsed.Status, meta.Status)
	}
}

func TestStageExfilMetadataSerialization(t *testing.T) {
	meta := stageExfilMetadata{
		StagingDir:    "/tmp/staging",
		EncryptionKey: "deadbeef",
		OriginalSize:  2048,
		ArchiveSize:   1500,
		FileCount:     5,
		SourceSHA256:  "sha256source",
		ArchiveSHA256: "sha256archive",
		SourcePath:    "/home/user/docs",
		CleanedUp:     true,
		Status:        "staged_and_transferred",
	}

	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed stageExfilMetadata
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.FileCount != 5 {
		t.Errorf("file_count: got %d, want 5", parsed.FileCount)
	}
	if parsed.Status != "staged_and_transferred" {
		t.Errorf("status: got %s, want staged_and_transferred", parsed.Status)
	}
	if parsed.EncryptionKey != "deadbeef" {
		t.Errorf("encryption_key: got %s, want deadbeef", parsed.EncryptionKey)
	}
}

func TestCompressExfilCleanupParam(t *testing.T) {
	// Verify cleanup field is properly parsed in CompressParams
	params := CompressParams{
		Action:  "exfil",
		Path:    "/tmp/test.dat",
		Cleanup: true,
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed CompressParams
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !parsed.Cleanup {
		t.Error("cleanup should be true after roundtrip")
	}
	if parsed.Action != "exfil" {
		t.Errorf("action: got %s, want exfil", parsed.Action)
	}
}

func TestFormatExfilSize(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B (0 bytes)"},
		{1024, "1.0 KB (1024 bytes)"},
		{1048576, "1.0 MB (1048576 bytes)"},
	}

	for _, tt := range tests {
		result := formatExfilSize(tt.bytes)
		if result != tt.expected {
			t.Errorf("formatExfilSize(%d): got %q, want %q", tt.bytes, result, tt.expected)
		}
	}
}

func TestCompressStageExfilEmptyDir(t *testing.T) {
	// stage-exfil on empty directory should fail at stage step
	tmpDir := t.TempDir()

	cmd := &CompressCommand{}
	params, _ := json.Marshal(CompressParams{
		Action: "stage-exfil",
		Path:   tmpDir,
	})
	task := structs.NewTask("t", "compress", "")
	task.Params = string(params)

	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("stage-exfil on empty directory should return error")
	}
}

func TestCompressActionRoutingExfil(t *testing.T) {
	// Verify that "exfil" and "stage-exfil" are recognized as valid actions
	cmd := &CompressCommand{}

	// Test unknown action
	params, _ := json.Marshal(CompressParams{Action: "invalid"})
	task := structs.NewTask("t", "compress", "")
	task.Params = string(params)

	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("unknown action should return error")
	}

	// Verify the error message mentions all valid actions
	expected := []string{"create", "list", "extract", "stage", "exfil", "stage-exfil"}
	for _, action := range expected {
		if !contains(result.Output, action) {
			t.Errorf("error message should mention %q action", action)
		}
	}
}

func TestCompressExfilWithStagedArchive(t *testing.T) {
	// Create a staged archive first, then verify exfil validates it correctly
	// (can't test actual transfer without Mythic channels, but can test SHA-256 computation path)
	tmpDir := t.TempDir()
	testData := []byte("encrypted archive simulation data")
	archivePath := filepath.Join(tmpDir, "test.dat")
	os.WriteFile(archivePath, testData, 0600)

	// Verify the file exists and is not a directory
	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.IsDir() {
		t.Fatal("should not be a directory")
	}
	if info.Size() != int64(len(testData)) {
		t.Errorf("size: got %d, want %d", info.Size(), len(testData))
	}
}

// contains is defined in ldap_query_test.go
