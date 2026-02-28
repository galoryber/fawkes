package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestLastReturnsJSON(t *testing.T) {
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	var entries []lastLoginEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Errorf("expected valid JSON output: %v (got: %s)", err, result.Output)
	}
}

func TestLastWithEmptyJSON(t *testing.T) {
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: "{}"})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestLastWithCount(t *testing.T) {
	params, _ := json.Marshal(lastArgs{Count: 5})
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestLastWithUserFilter(t *testing.T) {
	params, _ := json.Marshal(lastArgs{Count: 10, User: "nonexistentuser12345"})
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestLastDefaultCount(t *testing.T) {
	params, _ := json.Marshal(lastArgs{Count: -1})
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestLastLoginEntryJSON(t *testing.T) {
	entry := lastLoginEntry{
		User:      "gary",
		TTY:       "pts/0",
		From:      "192.168.1.1",
		LoginTime: "2025-01-15 10:30:00",
		Duration:  "01:25",
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded lastLoginEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded.User != "gary" || decoded.TTY != "pts/0" || decoded.From != "192.168.1.1" {
		t.Errorf("unexpected decoded values: %+v", decoded)
	}
}

func TestExtractCString(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"normal", []byte{'h', 'e', 'l', 'l', 'o', 0, 0, 0}, "hello"},
		{"empty", []byte{0, 0, 0}, ""},
		{"full", []byte{'a', 'b', 'c'}, "abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCString(tt.data)
			if got != tt.want {
				t.Errorf("extractCString = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectRecordSize(t *testing.T) {
	data := make([]byte, 768)
	size := detectRecordSize(data)
	if size != 384 {
		t.Errorf("expected 384, got %d", size)
	}

	small := make([]byte, 10)
	size = detectRecordSize(small)
	if size != 0 {
		t.Errorf("expected 0 for small data, got %d", size)
	}
}
