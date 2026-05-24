package agentfunctions

import (
	"testing"
)

func TestParseTimestamp_RFC3339(t *testing.T) {
	ts, err := parseTimestamp("2026-05-24T12:30:00Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts == 0 {
		t.Error("expected non-zero timestamp")
	}
}

func TestParseTimestamp_RFC3339Nano(t *testing.T) {
	ts, err := parseTimestamp("2026-05-24T12:30:00.123456789Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts == 0 {
		t.Error("expected non-zero timestamp")
	}
}

func TestParseTimestamp_Empty(t *testing.T) {
	ts, err := parseTimestamp("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts != 0 {
		t.Errorf("expected 0 for empty string, got %d", ts)
	}
}

func TestParseTimestamp_Invalid(t *testing.T) {
	_, err := parseTimestamp("not-a-timestamp")
	if err == nil {
		t.Error("expected error for invalid timestamp")
	}
}

func TestParseTimestamp_WithOffset(t *testing.T) {
	ts, err := parseTimestamp("2026-05-24T07:30:00-05:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts == 0 {
		t.Error("expected non-zero timestamp")
	}
}
