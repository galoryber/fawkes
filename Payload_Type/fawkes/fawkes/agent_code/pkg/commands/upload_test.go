package commands

import (
	"encoding/json"
	"fawkes/pkg/structs"
	"testing"
)

func TestUploadName(t *testing.T) {
	cmd := &UploadCommand{}
	if cmd.Name() != "upload" {
		t.Errorf("expected 'upload', got '%s'", cmd.Name())
	}
}

func TestUploadDescription(t *testing.T) {
	cmd := &UploadCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestUploadInvalidJSON(t *testing.T) {
	cmd := &UploadCommand{}
	result := cmd.Execute(structs.Task{Params: "not-json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got '%s'", result.Status)
	}
	if !result.Completed {
		t.Error("should be completed on error")
	}
}

func TestUploadArgsStruct(t *testing.T) {
	args := UploadArgs{
		FileID:     "test-file-id",
		RemotePath: "/tmp/test.txt",
		Overwrite:  true,
	}
	data, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed UploadArgs
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if parsed.FileID != "test-file-id" {
		t.Errorf("FileID: expected 'test-file-id', got '%s'", parsed.FileID)
	}
	if parsed.RemotePath != "/tmp/test.txt" {
		t.Errorf("RemotePath: expected '/tmp/test.txt', got '%s'", parsed.RemotePath)
	}
	if !parsed.Overwrite {
		t.Error("Overwrite should be true")
	}
}
