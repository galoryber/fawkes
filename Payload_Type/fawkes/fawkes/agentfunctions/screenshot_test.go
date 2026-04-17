package agentfunctions

import (
	"strings"
	"testing"
)

func TestScreenshotOPSECMessage_Single(t *testing.T) {
	msg := screenshotOPSECMessage("single", 5, 60)
	if !strings.Contains(msg, "OPSEC WARNING") {
		t.Errorf("expected OPSEC WARNING prefix, got %q", msg)
	}
	if strings.Contains(msg, "recording") {
		t.Errorf("single action message should not mention recording, got %q", msg)
	}
}

func TestScreenshotOPSECMessage_Record(t *testing.T) {
	msg := screenshotOPSECMessage("record", 5, 60)
	if !strings.Contains(msg, "60s") {
		t.Errorf("record message should include duration 60s, got %q", msg)
	}
	if !strings.Contains(msg, "5s") {
		t.Errorf("record message should include interval 5s, got %q", msg)
	}
	if !strings.Contains(msg, "jobkill") {
		t.Errorf("record message should mention jobkill, got %q", msg)
	}
}

func TestScreenshotOPSECMessage_RecordCustomParams(t *testing.T) {
	msg := screenshotOPSECMessage("record", 10, 300)
	if !strings.Contains(msg, "300s") {
		t.Errorf("expected 300s in message, got %q", msg)
	}
	if !strings.Contains(msg, "10s") {
		t.Errorf("expected 10s in message, got %q", msg)
	}
}

func TestParseScreenshotRecordResult_Valid(t *testing.T) {
	json := `{"action":"record","frames_captured":12,"actual_duration":"60s","stopped_by":"duration"}`
	result, ok := parseScreenshotRecordResult(json)
	if !ok {
		t.Fatal("expected ok=true for valid record JSON")
	}
	if result.Frames != 12 {
		t.Errorf("expected 12 frames, got %d", result.Frames)
	}
	if result.Duration != "60s" {
		t.Errorf("expected '60s' duration, got %q", result.Duration)
	}
	if result.StoppedBy != "duration" {
		t.Errorf("expected 'duration' stopped_by, got %q", result.StoppedBy)
	}
}

func TestParseScreenshotRecordResult_WrongAction(t *testing.T) {
	json := `{"action":"single","frames_captured":1}`
	_, ok := parseScreenshotRecordResult(json)
	if ok {
		t.Error("expected ok=false for non-record action")
	}
}

func TestParseScreenshotRecordResult_InvalidJSON(t *testing.T) {
	_, ok := parseScreenshotRecordResult("not json")
	if ok {
		t.Error("expected ok=false for invalid JSON")
	}
}

func TestParseScreenshotRecordResult_Empty(t *testing.T) {
	_, ok := parseScreenshotRecordResult("")
	if ok {
		t.Error("expected ok=false for empty string")
	}
}
