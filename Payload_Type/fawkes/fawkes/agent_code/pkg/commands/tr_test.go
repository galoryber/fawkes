package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestTrTranslate(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("hello world\n"), 0644)

	params, _ := json.Marshal(trArgs{Path: f, From: "[:lower:]", To: "[:upper:]"})
	cmd := &TrCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "HELLO WORLD") {
		t.Fatalf("expected HELLO WORLD, got: %s", result.Output)
	}
}

func TestTrDelete(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("abc123def456\n"), 0644)

	params, _ := json.Marshal(trArgs{Path: f, Delete: "[:digit:]"})
	cmd := &TrCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "abcdef") {
		t.Fatalf("expected abcdef, got: %s", result.Output)
	}
}

func TestTrSqueeze(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("aabbccdd\n"), 0644)

	params, _ := json.Marshal(trArgs{Path: f, Squeeze: true})
	cmd := &TrCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "abcd") {
		t.Fatalf("expected abcd, got: %s", result.Output)
	}
}

func TestTrRange(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("abc\n"), 0644)

	params, _ := json.Marshal(trArgs{Path: f, From: "a-c", To: "A-C"})
	cmd := &TrCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "ABC") {
		t.Fatalf("expected ABC, got: %s", result.Output)
	}
}

func TestTrNonexistent(t *testing.T) {
	params, _ := json.Marshal(trArgs{Path: "/nonexistent", From: "a", To: "b"})
	cmd := &TrCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestTrNoParams(t *testing.T) {
	cmd := &TrCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestTrNoAction(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("test\n"), 0644)

	params, _ := json.Marshal(trArgs{Path: f})
	cmd := &TrCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestExpandTrClass(t *testing.T) {
	result := expandTrClass("[:digit:]")
	if result != "0123456789" {
		t.Fatalf("expected digits, got: %s", result)
	}

	result = expandTrClass("a-d")
	if result != "abcd" {
		t.Fatalf("expected abcd, got: %s", result)
	}
}
