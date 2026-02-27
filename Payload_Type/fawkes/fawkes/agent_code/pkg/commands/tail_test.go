package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestTailName(t *testing.T) {
	c := &TailCommand{}
	if c.Name() != "tail" {
		t.Errorf("expected 'tail', got '%s'", c.Name())
	}
}

func TestTailDescription(t *testing.T) {
	c := &TailCommand{}
	if c.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestTailEmptyParams(t *testing.T) {
	c := &TailCommand{}
	result := c.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestTailBadJSON(t *testing.T) {
	c := &TailCommand{}
	result := c.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestTailMissingPath(t *testing.T) {
	c := &TailCommand{}
	params, _ := json.Marshal(tailArgs{})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestTailNonexistentFile(t *testing.T) {
	c := &TailCommand{}
	params, _ := json.Marshal(tailArgs{Path: "/nonexistent/file.txt"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestTailDefaultLast10(t *testing.T) {
	f := createTailTestFile(t, 20)
	defer os.Remove(f)

	c := &TailCommand{}
	params, _ := json.Marshal(tailArgs{Path: f})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "last 10 lines") {
		t.Error("should say 'last 10 lines'")
	}
	// Should contain lines 11-20, not lines 1-10
	if strings.Contains(result.Output, "line 1\n") {
		t.Error("should not contain line 1")
	}
	if !strings.Contains(result.Output, "line 20") {
		t.Error("should contain line 20")
	}
}

func TestTailSpecificLineCount(t *testing.T) {
	f := createTailTestFile(t, 20)
	defer os.Remove(f)

	c := &TailCommand{}
	params, _ := json.Marshal(tailArgs{Path: f, Lines: 5})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "last 5 lines") {
		t.Error("should say 'last 5 lines'")
	}
	if !strings.Contains(result.Output, "line 16") {
		t.Error("should contain line 16")
	}
	if !strings.Contains(result.Output, "line 20") {
		t.Error("should contain line 20")
	}
}

func TestTailHeadMode(t *testing.T) {
	f := createTailTestFile(t, 20)
	defer os.Remove(f)

	c := &TailCommand{}
	params, _ := json.Marshal(tailArgs{Path: f, Lines: 5, Head: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "first 5 lines") {
		t.Error("should say 'first 5 lines'")
	}
	if !strings.Contains(result.Output, "line 1") {
		t.Error("should contain line 1")
	}
	if !strings.Contains(result.Output, "line 5") {
		t.Error("should contain line 5")
	}
	if strings.Contains(result.Output, "line 6") {
		t.Error("should not contain line 6")
	}
}

func TestTailFewerLinesThanRequested(t *testing.T) {
	f := createTailTestFile(t, 3)
	defer os.Remove(f)

	c := &TailCommand{}
	params, _ := json.Marshal(tailArgs{Path: f, Lines: 10})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "last 3 lines") {
		t.Error("should say 'last 3 lines' when file has fewer lines")
	}
}

func TestTailBytesFromEnd(t *testing.T) {
	f, err := os.CreateTemp("", "tail_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write([]byte("hello world"))
	f.Close()

	c := &TailCommand{}
	params, _ := json.Marshal(tailArgs{Path: f.Name(), Bytes: 5})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "world") {
		t.Error("should contain 'world' (last 5 bytes)")
	}
	if !strings.Contains(result.Output, "last 5 bytes") {
		t.Error("should say 'last 5 bytes'")
	}
}

func TestTailBytesFromBeginning(t *testing.T) {
	f, err := os.CreateTemp("", "tail_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write([]byte("hello world"))
	f.Close()

	c := &TailCommand{}
	params, _ := json.Marshal(tailArgs{Path: f.Name(), Bytes: 5, Head: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "hello") {
		t.Error("should contain 'hello' (first 5 bytes)")
	}
	if !strings.Contains(result.Output, "first 5 bytes") {
		t.Error("should say 'first 5 bytes'")
	}
}

func TestTailBytesExceedsFileSize(t *testing.T) {
	f, err := os.CreateTemp("", "tail_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write([]byte("short"))
	f.Close()

	c := &TailCommand{}
	params, _ := json.Marshal(tailArgs{Path: f.Name(), Bytes: 1000})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "short") {
		t.Error("should contain full file content")
	}
}

func TestTailShowsFileSize(t *testing.T) {
	f := createTailTestFile(t, 5)
	defer os.Remove(f)

	c := &TailCommand{}
	params, _ := json.Marshal(tailArgs{Path: f})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	// Should show file size in parentheses
	if !strings.Contains(result.Output, "B)") {
		t.Error("should show file size")
	}
}

func TestTailEmptyFile(t *testing.T) {
	f, err := os.CreateTemp("", "tail_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	c := &TailCommand{}
	params, _ := json.Marshal(tailArgs{Path: f.Name()})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "last 0 lines") {
		t.Error("empty file should report 0 lines")
	}
}

// createTailTestFile creates a temp file with N lines for testing
func createTailTestFile(t *testing.T, lines int) string {
	t.Helper()
	f, err := os.CreateTemp("", "tail_test_*")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= lines; i++ {
		fmt.Fprintf(f, "line %d\n", i)
	}
	f.Close()
	return f.Name()
}
