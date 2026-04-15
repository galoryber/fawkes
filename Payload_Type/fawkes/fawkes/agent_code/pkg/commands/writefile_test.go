package commands

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestWriteFileName(t *testing.T) {
	c := &WriteFileCommand{}
	if c.Name() != "write-file" {
		t.Errorf("expected 'write-file', got '%s'", c.Name())
	}
}

func TestWriteFileDescription(t *testing.T) {
	c := &WriteFileCommand{}
	if c.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestWriteFileEmptyParams(t *testing.T) {
	c := &WriteFileCommand{}
	result := c.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestWriteFileBadJSON(t *testing.T) {
	c := &WriteFileCommand{}
	result := c.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestWriteFileMissingPath(t *testing.T) {
	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Content: "hello"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestWriteFileMissingContent(t *testing.T) {
	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Path: "/tmp/test"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestWriteFileBasicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Path: path, Content: "hello world"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello world" {
		t.Errorf("expected 'hello world', got '%s'", string(data))
	}
}

func TestWriteFileOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("original"), 0644)

	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Path: path, Content: "replaced"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	data, _ := os.ReadFile(path)
	if string(data) != "replaced" {
		t.Errorf("expected 'replaced', got '%s'", string(data))
	}
}

func TestWriteFileAppend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("first"), 0644)

	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Path: path, Content: " second", Append: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	data, _ := os.ReadFile(path)
	if string(data) != "first second" {
		t.Errorf("expected 'first second', got '%s'", string(data))
	}
}

func TestWriteFileBase64(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")

	original := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
	encoded := base64.StdEncoding.EncodeToString(original)

	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Path: path, Content: encoded, Base64: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	data, _ := os.ReadFile(path)
	if len(data) != len(original) {
		t.Fatalf("expected %d bytes, got %d", len(original), len(data))
	}
	for i, b := range data {
		if b != original[i] {
			t.Errorf("byte %d: expected 0x%02x, got 0x%02x", i, original[i], b)
		}
	}
}

func TestWriteFileInvalidBase64(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")

	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Path: path, Content: "not!valid!base64!!!", Base64: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error for invalid base64, got %s", result.Status)
	}
}

func TestWriteFileMkDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b", "c", "test.txt")

	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Path: path, Content: "nested", MkDirs: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	data, _ := os.ReadFile(path)
	if string(data) != "nested" {
		t.Errorf("expected 'nested', got '%s'", string(data))
	}
}

func TestWriteFileMissingParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent", "test.txt")

	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Path: path, Content: "test"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error without mkdir flag, got %s", result.Status)
	}
}

func TestWriteFileOutputMessage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	c := &WriteFileCommand{}

	// Test write message
	params, _ := json.Marshal(writeFileArgs{Path: path, Content: "hello"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatal(result.Output)
	}
	if result.Output != "[+] Wrote 5 bytes to "+path {
		t.Errorf("unexpected output: %s", result.Output)
	}

	// Test append message
	params, _ = json.Marshal(writeFileArgs{Path: path, Content: " more", Append: true})
	result = c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatal(result.Output)
	}
	if result.Output != "[+] Appended 5 bytes to "+path {
		t.Errorf("unexpected output: %s", result.Output)
	}
}

// --- Deface action tests (T1491 web defacement) ---

func TestDefaceNoConfirm(t *testing.T) {
	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Action: "deface", Path: "/var/www/html/index.html"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "DEFACE") {
		t.Errorf("expected DEFACE safety gate error, got: %s", result.Output)
	}
}

func TestDefaceWrongConfirm(t *testing.T) {
	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Action: "deface", Path: "/tmp/test.html", Confirm: "yes"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "DEFACE") {
		t.Errorf("expected DEFACE safety gate error for wrong confirm, got: %s", result.Output)
	}
}

func TestDefaceDefaultContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.html")
	os.WriteFile(path, []byte("<html>original</html>"), 0644)

	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Action: "deface", Path: path, Confirm: "DEFACE"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("deface failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Defaced") {
		t.Errorf("expected Defaced in output: %s", result.Output)
	}
	content, _ := os.ReadFile(path)
	if !strings.Contains(string(content), "DEFACED") {
		t.Error("file should contain default defacement message")
	}
	if !strings.Contains(string(content), "Purple team") {
		t.Error("file should contain purple team disclaimer")
	}
}

func TestDefaceCustomContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.html")
	os.WriteFile(path, []byte("<html>original</html>"), 0644)

	customHTML := "<h1>Custom defacement message</h1>"
	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Action: "deface", Path: path, Content: customHTML, Confirm: "DEFACE"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("deface failed: %s", result.Output)
	}
	content, _ := os.ReadFile(path)
	if string(content) != customHTML {
		t.Errorf("expected custom content, got: %s", string(content))
	}
}

func TestDefaceNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new_index.html")

	c := &WriteFileCommand{}
	params, _ := json.Marshal(writeFileArgs{Action: "deface", Path: path, Confirm: "DEFACE"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("deface on new file failed: %s", result.Output)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("defaced file should exist")
	}
}
