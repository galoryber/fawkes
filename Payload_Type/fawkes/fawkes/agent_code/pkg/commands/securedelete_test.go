package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSecureDeleteFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.txt")
	os.WriteFile(tmp, []byte("sensitive data here"), 0644)

	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Path: tmp})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("file should not exist after secure delete")
	}
}

func TestSecureDeleteDefaultPasses(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.txt")
	os.WriteFile(tmp, []byte("data"), 0644)

	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Path: tmp})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "3 passes") {
		t.Errorf("expected default 3 passes in output: %s", result.Output)
	}
}

func TestSecureDeleteCustomPasses(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.txt")
	os.WriteFile(tmp, []byte("data"), 0644)

	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Path: tmp, Passes: 5})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "5 passes") {
		t.Errorf("expected 5 passes in output: %s", result.Output)
	}
}

func TestSecureDeleteDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "testdir")
	os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	os.WriteFile(filepath.Join(dir, "file1.txt"), []byte("data1"), 0644)
	os.WriteFile(filepath.Join(dir, "sub", "file2.txt"), []byte("data2"), 0644)

	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Path: dir})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "2 files") {
		t.Errorf("expected 2 files deleted: %s", result.Output)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("directory should not exist after secure delete")
	}
}

func TestSecureDeleteNonexistent(t *testing.T) {
	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Path: "/tmp/nonexistent_securedelete_test"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error for nonexistent file, got %s", result.Status)
	}
}

func TestSecureDeleteNoParams(t *testing.T) {
	cmd := &SecureDeleteCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error with no params")
	}
}

func TestSecureDeleteEmptyPath(t *testing.T) {
	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Path: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error with empty path")
	}
}

func TestSecureDeleteLargeFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "large.bin")
	// Create a 100KB file
	data := make([]byte, 100*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	os.WriteFile(tmp, data, 0644)

	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Path: tmp, Passes: 1})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("large file should not exist after secure delete")
	}
}

func TestSecureDeleteEmptyFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.txt")
	os.WriteFile(tmp, []byte{}, 0644)

	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Path: tmp})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("empty file should not exist after secure delete")
	}
}

func TestSecureDeleteFileFunction(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "func_test.txt")
	original := []byte("original content that should be overwritten")
	os.WriteFile(tmp, original, 0644)

	err := secureDeleteFile(tmp, int64(len(original)), 1)
	if err != nil {
		t.Fatalf("secureDeleteFile failed: %v", err)
	}

	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("file should be removed after secureDeleteFile")
	}
}
