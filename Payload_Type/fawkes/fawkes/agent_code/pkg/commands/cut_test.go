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

func TestParseRangesEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		spec   string
		maxVal int
		want   []int
	}{
		{"empty spec", "", 10, nil},
		{"empty parts with commas", ",,", 10, nil},
		{"whitespace parts", " , , ", 10, nil},
		{"open-start range -3", "-3", 5, []int{1, 2, 3}},
		{"start below 1 clamped", "0-3", 10, []int{1, 2, 3}},
		{"end exceeds max clamped", "8-20", 10, []int{8, 9, 10}},
		{"non-numeric single value", "abc", 10, nil},
		{"non-numeric range start", "abc-5", 10, []int{1, 2, 3, 4, 5}},
		{"non-numeric range end", "3-xyz", 10, []int{3, 4, 5, 6, 7, 8, 9, 10}},
		{"duplicate values", "1,1,2,2", 10, []int{1, 2}},
		{"overlapping ranges", "1-3,2-4", 10, []int{1, 2, 3, 4}},
		{"single value out of range high", "15", 10, nil},
		{"single value at boundary", "10", 10, []int{10}},
		{"max=0 returns nothing", "1-5", 0, nil},
		{"single value equals maxVal", "5", 5, []int{5}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRanges(tt.spec, tt.maxVal)
			if len(got) != len(tt.want) {
				t.Errorf("parseRanges(%q, %d) = %v (len %d), want %v (len %d)",
					tt.spec, tt.maxVal, got, len(got), tt.want, len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseRanges(%q, %d)[%d] = %d, want %d",
						tt.spec, tt.maxVal, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestCutBadJSON(t *testing.T) {
	cmd := &CutCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for bad JSON, got %s", result.Status)
	}
}

func TestCutDefaultDelimiter(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "tabs.txt")
	os.WriteFile(f, []byte("a\tb\tc\n1\t2\t3\n"), 0644)

	params, _ := json.Marshal(cutArgs{Path: f, Fields: "1,3"})
	cmd := &CutCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "a\tc") {
		t.Errorf("expected tab-separated output, got: %s", result.Output)
	}
}

func TestCutOpenStartRange(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("a,b,c,d,e\n"), 0644)

	params, _ := json.Marshal(cutArgs{Path: f, Delimiter: ",", Fields: "-3"})
	cmd := &CutCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "a,b,c") {
		t.Errorf("expected a,b,c for range -3, got: %s", result.Output)
	}
}
