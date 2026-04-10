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

func TestSecureRemove(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "secure_remove_test.txt")
	os.WriteFile(tmp, []byte("sensitive temp data"), 0644)

	secureRemove(tmp)

	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("file should not exist after secureRemove")
	}
}

func TestSecureRemoveNonexistent(t *testing.T) {
	// Should not panic on nonexistent path
	secureRemove(filepath.Join(t.TempDir(), "does_not_exist"))
}

// --- Wipe action tests (T1485 data destruction) ---

func TestWipeNoConfirm(t *testing.T) {
	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Action: "wipe", Path: "/tmp/test"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "DESTROY") {
		t.Errorf("expected DESTROY safety gate error, got: %s", result.Output)
	}
}

func TestWipeFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "wipe_test.txt")
	os.WriteFile(tmp, []byte("sensitive data to wipe"), 0644)

	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Action: "wipe", Path: tmp, Confirm: "DESTROY"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("wipe failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Wiped") {
		t.Errorf("expected Wiped in output: %s", result.Output)
	}
	if !strings.Contains(result.Output, "zeros+ones+random") {
		t.Errorf("expected pattern description: %s", result.Output)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("file should not exist after wipe")
	}
}

func TestWipeDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wipe_dir")
	os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("data1"), 0644)
	os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("data2"), 0644)

	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Action: "wipe", Path: dir, Confirm: "DESTROY"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("wipe dir failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "2 files") {
		t.Errorf("expected 2 files: %s", result.Output)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("directory should not exist after wipe")
	}
}

func TestWipeCustomPasses(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "wipe_passes.txt")
	os.WriteFile(tmp, []byte("test data"), 0644)

	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Action: "wipe", Path: tmp, Passes: 3, Confirm: "DESTROY"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("wipe failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "3 passes") {
		t.Errorf("expected 3 passes: %s", result.Output)
	}
}

func TestWipeDefaultPasses(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "wipe_default.txt")
	os.WriteFile(tmp, []byte("test data"), 0644)

	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Action: "wipe", Path: tmp, Confirm: "DESTROY"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("wipe failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "7 passes") {
		t.Errorf("expected default 7 passes: %s", result.Output)
	}
}

// --- Wipe-MBR action tests (T1561 disk wipe) ---

func TestWipeMBRNoConfirm(t *testing.T) {
	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Action: "wipe-mbr", Path: "/dev/sda"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "DESTROY") {
		t.Errorf("expected DESTROY safety gate error, got: %s", result.Output)
	}
}

func TestWipeMBRWrongConfirm(t *testing.T) {
	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Action: "wipe-mbr", Path: "/dev/sda", Confirm: "yes"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "DESTROY") {
		t.Errorf("expected DESTROY safety gate error for wrong confirm, got: %s", result.Output)
	}
}

func TestWipeMBREmptyPath(t *testing.T) {
	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Action: "wipe-mbr", Confirm: "DESTROY"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "path") {
		t.Errorf("expected path required error, got: %s", result.Output)
	}
}

func TestWipeMBRNonexistentDevice(t *testing.T) {
	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Action: "wipe-mbr", Path: "/dev/nonexistent_disk_xyz", Confirm: "DESTROY"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent device, got: %s", result.Output)
	}
}

func TestWipeMBROnRegularFile(t *testing.T) {
	// wipe-mbr should work on regular files too (for testing)
	tmp := filepath.Join(t.TempDir(), "fake_mbr.bin")
	// Create a 2KB file simulating a disk device
	data := make([]byte, 2048)
	for i := range data {
		data[i] = 0xFF
	}
	os.WriteFile(tmp, data, 0644)

	cmd := &SecureDeleteCommand{}
	params, _ := json.Marshal(secureDeleteArgs{Action: "wipe-mbr", Path: tmp, Confirm: "DESTROY"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("wipe-mbr failed on regular file: %s", result.Output)
	}
	if !strings.Contains(result.Output, "MBR/GPT wiped") {
		t.Errorf("expected MBR/GPT wiped in output: %s", result.Output)
	}
	if !strings.Contains(result.Output, "1024 bytes") {
		t.Errorf("expected 1024 bytes in output: %s", result.Output)
	}
	// Verify first 1024 bytes are zeros
	content, _ := os.ReadFile(tmp)
	for i := 0; i < 1024 && i < len(content); i++ {
		if content[i] != 0 {
			t.Errorf("byte %d should be 0, got %d", i, content[i])
			break
		}
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
