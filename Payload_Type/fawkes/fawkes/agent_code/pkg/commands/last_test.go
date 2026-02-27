package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestLastNoParams(t *testing.T) {
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
	// Should return something (even if no history on CI)
	if result.Output == "" {
		t.Fatal("expected non-empty output")
	}
}

func TestLastWithEmptyJSON(t *testing.T) {
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: "{}"})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
}

func TestLastWithCount(t *testing.T) {
	params, _ := json.Marshal(lastArgs{Count: 5})
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
}

func TestLastWithUserFilter(t *testing.T) {
	params, _ := json.Marshal(lastArgs{Count: 10, User: "nonexistentuser12345"})
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
}

func TestLastDefaultCount(t *testing.T) {
	// Negative count should default to 25
	params, _ := json.Marshal(lastArgs{Count: -1})
	cmd := &LastCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
}

func TestFormatLastEntry(t *testing.T) {
	entry := formatLastEntry("gary", "pts/0", "192.168.1.1", "2025-01-15 10:30:00", "01:25")
	if !strings.Contains(entry, "gary") {
		t.Error("expected user in output")
	}
	if !strings.Contains(entry, "pts/0") {
		t.Error("expected tty in output")
	}
	if !strings.Contains(entry, "192.168.1.1") {
		t.Error("expected host in output")
	}
}

func TestFormatLastEntryEmptyFields(t *testing.T) {
	entry := formatLastEntry("root", "", "", "2025-01-15 10:30:00", "")
	if !strings.Contains(entry, "-") {
		t.Error("expected dash for empty fields")
	}
}

func TestLastHeader(t *testing.T) {
	header := lastHeader()
	if !strings.Contains(header, "USER") {
		t.Error("expected USER in header")
	}
	if !strings.Contains(header, "TTY") {
		t.Error("expected TTY in header")
	}
	if !strings.Contains(header, "FROM") {
		t.Error("expected FROM in header")
	}
	if !strings.Contains(header, "LOGIN TIME") {
		t.Error("expected LOGIN TIME in header")
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
	// Data that's exactly 384*2 = 768 bytes should detect 384
	data := make([]byte, 768)
	size := detectRecordSize(data)
	if size != 384 {
		t.Errorf("expected 384, got %d", size)
	}

	// Data too small
	small := make([]byte, 10)
	size = detectRecordSize(small)
	if size != 0 {
		t.Errorf("expected 0 for small data, got %d", size)
	}
}
