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

func TestBase64Name(t *testing.T) {
	c := &Base64Command{}
	if c.Name() != "base64" {
		t.Errorf("expected 'base64', got '%s'", c.Name())
	}
}

func TestBase64Description(t *testing.T) {
	c := &Base64Command{}
	if c.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestBase64EmptyParams(t *testing.T) {
	c := &Base64Command{}
	result := c.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestBase64BadJSON(t *testing.T) {
	c := &Base64Command{}
	result := c.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestBase64MissingInput(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestBase64InvalidAction(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "invalid", Input: "test"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestBase64EncodeString(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode", Input: "hello world"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	expected := base64.StdEncoding.EncodeToString([]byte("hello world"))
	if !strings.Contains(result.Output, expected) {
		t.Errorf("expected output to contain '%s', got: %s", expected, result.Output)
	}
}

func TestBase64DecodeString(t *testing.T) {
	c := &Base64Command{}
	encoded := base64.StdEncoding.EncodeToString([]byte("hello world"))
	params, _ := json.Marshal(base64Args{Action: "decode", Input: encoded})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "hello world") {
		t.Errorf("expected 'hello world' in output, got: %s", result.Output)
	}
}

func TestBase64DefaultActionEncode(t *testing.T) {
	c := &Base64Command{}
	// No action specified — should default to encode
	params, _ := json.Marshal(base64Args{Input: "test"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	expected := base64.StdEncoding.EncodeToString([]byte("test"))
	if !strings.Contains(result.Output, expected) {
		t.Error("default action should encode")
	}
}

func TestBase64EncodeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.txt")
	os.WriteFile(path, []byte("file content"), 0644)

	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode", Input: path, File: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	expected := base64.StdEncoding.EncodeToString([]byte("file content"))
	if !strings.Contains(result.Output, expected) {
		t.Error("should contain base64-encoded file content")
	}
}

func TestBase64DecodeToFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "output.bin")
	encoded := base64.StdEncoding.EncodeToString([]byte("decoded content"))

	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "decode", Input: encoded, Output: outPath})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "decoded content" {
		t.Errorf("expected 'decoded content', got '%s'", string(data))
	}
}

func TestBase64EncodeToFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "encoded.txt")

	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode", Input: "test data", Output: outPath})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	expected := base64.StdEncoding.EncodeToString([]byte("test data"))
	if string(data) != expected {
		t.Errorf("expected '%s', got '%s'", expected, string(data))
	}
}

func TestBase64InvalidBase64(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "decode", Input: "not!valid!base64!!!"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error for invalid base64, got %s", result.Status)
	}
}

func TestBase64NonexistentFile(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode", Input: "/nonexistent/file", File: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestBase64BinaryContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary.bin")
	binData := []byte{0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F}
	os.WriteFile(path, binData, 0644)

	// Encode
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode", Input: path, File: true})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("encode failed: %s", result.Output)
	}

	expected := base64.StdEncoding.EncodeToString(binData)
	if !strings.Contains(result.Output, expected) {
		t.Error("should contain correct base64 for binary data")
	}

	// Decode back
	outPath := filepath.Join(dir, "restored.bin")
	params, _ = json.Marshal(base64Args{Action: "decode", Input: expected, Output: outPath})
	result = c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("decode failed: %s", result.Output)
	}

	restored, _ := os.ReadFile(outPath)
	if len(restored) != len(binData) {
		t.Fatalf("expected %d bytes, got %d", len(binData), len(restored))
	}
	for i, b := range restored {
		if b != binData[i] {
			t.Errorf("byte %d: expected 0x%02x, got 0x%02x", i, binData[i], b)
		}
	}
}
