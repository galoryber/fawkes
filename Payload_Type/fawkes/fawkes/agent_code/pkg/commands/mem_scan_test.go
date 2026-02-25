package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestMemScanCommand_Name(t *testing.T) {
	cmd := &MemScanCommand{}
	if cmd.Name() != "mem-scan" {
		t.Errorf("expected 'mem-scan', got %q", cmd.Name())
	}
}

func TestMemScanCommand_NoParams(t *testing.T) {
	cmd := &MemScanCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("expected error for no params")
	}
	if !strings.Contains(result.Output, "pattern is required") {
		t.Errorf("expected pattern error, got: %s", result.Output)
	}
}

func TestMemScanCommand_InvalidJSON(t *testing.T) {
	cmd := &MemScanCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
}

func TestMemScanCommand_EmptyPattern(t *testing.T) {
	cmd := &MemScanCommand{}
	params, _ := json.Marshal(memScanArgs{PID: 1, Pattern: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for empty pattern")
	}
}

func TestMemScanCommand_InvalidHex(t *testing.T) {
	cmd := &MemScanCommand{}
	params, _ := json.Marshal(memScanArgs{PID: 1, Pattern: "ZZZZ", Hex: true})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for invalid hex")
	}
	if !strings.Contains(result.Output, "invalid hex") {
		t.Errorf("expected hex error message, got: %s", result.Output)
	}
}

func TestSearchInRegion_BasicMatch(t *testing.T) {
	data := []byte("Hello World, this is a test string with PASSWORD=secret inside")
	matches := searchInRegion(data, 0x1000, []byte("PASSWORD"), 8, 50, nil)

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	m := matches[0]
	if m.Address != 0x1000+40 { // "PASSWORD" starts at offset 40
		t.Errorf("expected address 0x%X, got 0x%X", 0x1000+40, m.Address)
	}
	if m.MatchLen != 8 {
		t.Errorf("expected match len 8, got %d", m.MatchLen)
	}
}

func TestSearchInRegion_MultipleMatches(t *testing.T) {
	data := []byte("AAAA_BBBB_AAAA_CCCC_AAAA")
	matches := searchInRegion(data, 0x2000, []byte("AAAA"), 4, 50, nil)

	if len(matches) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(matches))
	}

	expected := []uint64{0x2000, 0x200A, 0x2014}
	for i, m := range matches {
		if m.Address != expected[i] {
			t.Errorf("match %d: expected address 0x%X, got 0x%X", i, expected[i], m.Address)
		}
	}
}

func TestSearchInRegion_MaxResults(t *testing.T) {
	data := []byte("AAAA_AAAA_AAAA_AAAA_AAAA")
	matches := searchInRegion(data, 0x3000, []byte("AAAA"), 2, 2, nil)

	if len(matches) != 2 {
		t.Fatalf("expected 2 matches (limited), got %d", len(matches))
	}
}

func TestSearchInRegion_NoMatch(t *testing.T) {
	data := []byte("Hello World")
	matches := searchInRegion(data, 0x4000, []byte("ZZZZ"), 4, 50, nil)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestSearchInRegion_ContextBytes(t *testing.T) {
	data := []byte("0123456789ABCDmatchEFGHIJKLMNOP0123")
	matches := searchInRegion(data, 0x5000, []byte("match"), 4, 50, nil)

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	m := matches[0]
	// Context should include 4 bytes before and after the match
	contextStr := string(m.Context)
	if !strings.Contains(contextStr, "ABCD") {
		t.Error("expected context to contain bytes before match")
	}
	if !strings.Contains(contextStr, "match") {
		t.Error("expected context to contain the match itself")
	}
	if !strings.Contains(contextStr, "EFGH") {
		t.Error("expected context to contain bytes after match")
	}
}

func TestSearchInRegion_HexPattern(t *testing.T) {
	// Test searching for raw bytes (as would come from hex decode)
	data := []byte{0x00, 0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00}
	pattern := []byte{0x4d, 0x5a, 0x90}
	matches := searchInRegion(data, 0x6000, pattern, 2, 50, nil)

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Address != 0x6001 {
		t.Errorf("expected address 0x6001, got 0x%X", matches[0].Address)
	}
}

func TestFormatScanSize(t *testing.T) {
	tests := []struct {
		input    uint64
		expected string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tc := range tests {
		result := formatScanSize(tc.input)
		if result != tc.expected {
			t.Errorf("formatScanSize(%d): expected %q, got %q", tc.input, tc.expected, result)
		}
	}
}

func TestFormatMemScanOutput_NoMatches(t *testing.T) {
	args := memScanArgs{PID: 1234, Pattern: "test", MaxResults: 50}
	result := formatMemScanOutput(args, nil, 10, 1048576, []byte("test"))

	if result.Status != "success" {
		t.Error("expected success status")
	}
	if !strings.Contains(result.Output, "PID 1234") {
		t.Error("expected PID in output")
	}
	if !strings.Contains(result.Output, "Matches found: 0") {
		t.Error("expected 0 matches")
	}
	if !strings.Contains(result.Output, "1.0 MB") {
		t.Errorf("expected formatted size, got: %s", result.Output)
	}
}

func TestFormatMemScanOutput_WithMatches(t *testing.T) {
	matches := []memScanMatch{
		{
			Address:    0x7FFE1234,
			RegionBase: 0x7FFE0000,
			Context:    []byte("before_PASSWORD=secret_after"),
			MatchStart: 7,
			MatchLen:   8,
		},
	}
	args := memScanArgs{PID: 5678, Pattern: "PASSWORD", MaxResults: 50}
	result := formatMemScanOutput(args, matches, 5, 2097152, []byte("PASSWORD"))

	if result.Status != "success" {
		t.Error("expected success status")
	}
	if !strings.Contains(result.Output, "Match 1: 0x7FFE1234") {
		t.Error("expected match address in output")
	}
	if !strings.Contains(result.Output, "Matches found: 1") {
		t.Error("expected 1 match")
	}
}

func TestFormatMemScanOutput_LimitReached(t *testing.T) {
	matches := make([]memScanMatch, 50)
	for i := range matches {
		matches[i] = memScanMatch{
			Address:    uint64(i * 0x100),
			RegionBase: 0x1000,
			Context:    []byte("ctx"),
			MatchStart: 0,
			MatchLen:   3,
		}
	}
	args := memScanArgs{PID: 1, Pattern: "test", MaxResults: 50}
	result := formatMemScanOutput(args, matches, 1, 4096, []byte("test"))

	if !strings.Contains(result.Output, "limit reached") {
		t.Error("expected limit reached message")
	}
}

func TestWriteHexDump(t *testing.T) {
	var sb strings.Builder
	data := []byte("Hello World!")
	writeHexDump(&sb, data, 0, 5, 0x1000)

	output := sb.String()
	// Should contain hex representation
	if !strings.Contains(output, "0x00001000") {
		t.Error("expected base address in hex dump")
	}
	// Match bytes (H=0x48, e=0x65, l=0x6c, l=0x6c, o=0x6f) should be in brackets
	if !strings.Contains(output, "[48]") {
		t.Error("expected highlighted match bytes in brackets")
	}
	// ASCII sidebar
	if !strings.Contains(output, "|Hello World!|") {
		t.Errorf("expected ASCII sidebar, got: %s", output)
	}
}
