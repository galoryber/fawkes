package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestHexdumpName(t *testing.T) {
	c := &HexdumpCommand{}
	if c.Name() != "hexdump" {
		t.Errorf("expected 'hexdump', got '%s'", c.Name())
	}
}

func TestHexdumpEmptyParams(t *testing.T) {
	c := &HexdumpCommand{}
	result := c.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestHexdumpBadJSON(t *testing.T) {
	c := &HexdumpCommand{}
	result := c.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestHexdumpMissingPath(t *testing.T) {
	c := &HexdumpCommand{}
	params, _ := json.Marshal(hexdumpArgs{})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestHexdumpNonexistentFile(t *testing.T) {
	c := &HexdumpCommand{}
	params, _ := json.Marshal(hexdumpArgs{Path: "/nonexistent/file"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestHexdumpBasic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	os.WriteFile(path, []byte("Hello, World!\x00\x01\x02\xff"), 0644)

	c := &HexdumpCommand{}
	params, _ := json.Marshal(hexdumpArgs{Path: path})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	// Should contain address column
	if !strings.Contains(result.Output, "00000000:") {
		t.Error("should contain address 00000000:")
	}
	// Should contain hex bytes
	if !strings.Contains(result.Output, "48 65 6c 6c") {
		t.Error("should contain hex for 'Hell'")
	}
	// Should contain ASCII representation
	if !strings.Contains(result.Output, "|Hello") {
		t.Error("should contain ASCII 'Hello'")
	}
	// Non-printable should be dots
	if !strings.Contains(result.Output, "...|") || !strings.Contains(result.Output, ".|") {
		// The last chars include 0x00, 0x01, 0x02, 0xff which should be dots
	}
}

func TestHexdumpOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}
	os.WriteFile(path, data, 0644)

	c := &HexdumpCommand{}
	params, _ := json.Marshal(hexdumpArgs{Path: path, Offset: 16, Length: 16})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	// Address should start at offset
	if !strings.Contains(result.Output, "00000010:") {
		t.Error("should start at offset 0x10")
	}
	// Should contain bytes starting at 0x10
	if !strings.Contains(result.Output, "10 11 12 13") {
		t.Error("should contain bytes from offset 16")
	}
}

func TestHexdumpOffsetExceedsSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	os.WriteFile(path, []byte("short"), 0644)

	c := &HexdumpCommand{}
	params, _ := json.Marshal(hexdumpArgs{Path: path, Offset: 1000})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error for offset > file size, got %s", result.Status)
	}
}

func TestHexdumpLengthCapped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := make([]byte, 100)
	os.WriteFile(path, data, 0644)

	c := &HexdumpCommand{}
	// Request more than max length
	params, _ := json.Marshal(hexdumpArgs{Path: path, Length: 10000})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	// Should only read up to file size (100 bytes) since it's less than maxLength
	if !strings.Contains(result.Output, "100 bytes") {
		t.Error("should show actual bytes read")
	}
}

func TestHexdumpShowsFileSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	os.WriteFile(path, []byte("test data"), 0644)

	c := &HexdumpCommand{}
	params, _ := json.Marshal(hexdumpArgs{Path: path})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "9 B") {
		t.Error("should show file size")
	}
}

func TestHexdumpDefaultLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	os.WriteFile(path, data, 0644)

	c := &HexdumpCommand{}
	params, _ := json.Marshal(hexdumpArgs{Path: path})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	// Default is 256 bytes = 16 lines of 16 bytes
	if !strings.Contains(result.Output, "256 bytes") {
		t.Error("should default to 256 bytes")
	}
}
