package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestCutFields(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/sh\n"), 0644)

	params, _ := json.Marshal(cutArgs{Path: f, Delimiter: ":", Fields: "1,7"})
	cmd := &CutCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "root:/bin/bash") {
		t.Fatalf("expected root:/bin/bash, got: %s", result.Output)
	}
}

func TestCutFieldRange(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("a,b,c,d,e\n1,2,3,4,5\n"), 0644)

	params, _ := json.Marshal(cutArgs{Path: f, Delimiter: ",", Fields: "2-4"})
	cmd := &CutCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "b,c,d") {
		t.Fatalf("expected b,c,d, got: %s", result.Output)
	}
}

func TestCutChars(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("Hello World\nFawkes Agent\n"), 0644)

	params, _ := json.Marshal(cutArgs{Path: f, Chars: "1-5"})
	cmd := &CutCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Hello") {
		t.Fatalf("expected Hello, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Fawke") {
		t.Fatalf("expected Fawke, got: %s", result.Output)
	}
}

func TestCutNonexistent(t *testing.T) {
	params, _ := json.Marshal(cutArgs{Path: "/nonexistent", Fields: "1"})
	cmd := &CutCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestCutNoFieldsOrChars(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("test\n"), 0644)

	params, _ := json.Marshal(cutArgs{Path: f})
	cmd := &CutCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestCutNoParams(t *testing.T) {
	cmd := &CutCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestParseRanges(t *testing.T) {
	r := parseRanges("1,3,5", 10)
	if len(r) != 3 || r[0] != 1 || r[1] != 3 || r[2] != 5 {
		t.Fatalf("expected [1,3,5], got %v", r)
	}

	r = parseRanges("2-4", 10)
	if len(r) != 3 || r[0] != 2 || r[1] != 3 || r[2] != 4 {
		t.Fatalf("expected [2,3,4], got %v", r)
	}

	r = parseRanges("3-", 5)
	if len(r) != 3 || r[0] != 3 || r[1] != 4 || r[2] != 5 {
		t.Fatalf("expected [3,4,5], got %v", r)
	}
}
