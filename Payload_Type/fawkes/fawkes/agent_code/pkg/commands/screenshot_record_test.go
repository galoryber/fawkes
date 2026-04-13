package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestParseScreenshotParams_Empty(t *testing.T) {
	task := structs.Task{Params: ""}
	params := parseScreenshotParams(task)
	if params.Action != "single" {
		t.Errorf("action: got %q, want %q", params.Action, "single")
	}
	if params.Interval != 5 {
		t.Errorf("interval: got %d, want 5", params.Interval)
	}
	if params.Duration != 60 {
		t.Errorf("duration: got %d, want 60", params.Duration)
	}
	if params.MaxFrames != 100 {
		t.Errorf("max_frames: got %d, want 100", params.MaxFrames)
	}
}

func TestParseScreenshotParams_Record(t *testing.T) {
	p, _ := json.Marshal(screenshotParams{
		Action:    "record",
		Interval:  10,
		Duration:  120,
		MaxFrames: 50,
	})
	task := structs.Task{Params: string(p)}
	params := parseScreenshotParams(task)
	if params.Action != "record" {
		t.Errorf("action: got %q, want %q", params.Action, "record")
	}
	if params.Interval != 10 {
		t.Errorf("interval: got %d, want 10", params.Interval)
	}
	if params.Duration != 120 {
		t.Errorf("duration: got %d, want 120", params.Duration)
	}
	if params.MaxFrames != 50 {
		t.Errorf("max_frames: got %d, want 50", params.MaxFrames)
	}
}

func TestParseScreenshotParams_Defaults(t *testing.T) {
	// Test that zero/negative values get defaults
	p, _ := json.Marshal(screenshotParams{
		Action:    "record",
		Interval:  -1,
		Duration:  0,
		MaxFrames: -5,
	})
	task := structs.Task{Params: string(p)}
	params := parseScreenshotParams(task)
	if params.Interval < 1 {
		t.Errorf("interval should be at least 1, got %d", params.Interval)
	}
	if params.Duration < 1 {
		t.Errorf("duration should be at least 1, got %d", params.Duration)
	}
	if params.MaxFrames < 1 {
		t.Errorf("max_frames should be at least 1, got %d", params.MaxFrames)
	}
}

func TestParseScreenshotParams_MaxClamping(t *testing.T) {
	p, _ := json.Marshal(screenshotParams{
		Action:    "record",
		Duration:  9999,
		MaxFrames: 99999,
	})
	task := structs.Task{Params: string(p)}
	params := parseScreenshotParams(task)
	if params.Duration > 600 {
		t.Errorf("duration should be clamped to 600, got %d", params.Duration)
	}
	if params.MaxFrames > 1000 {
		t.Errorf("max_frames should be clamped to 1000, got %d", params.MaxFrames)
	}
}

func TestParseScreenshotParams_InvalidJSON(t *testing.T) {
	task := structs.Task{Params: "not valid json"}
	params := parseScreenshotParams(task)
	// Should get defaults
	if params.Action != "single" {
		t.Errorf("action: got %q, want %q", params.Action, "single")
	}
	if params.Interval != 5 {
		t.Errorf("interval: got %d, want 5", params.Interval)
	}
}

func TestScreenshotRecordResult_JSON(t *testing.T) {
	result := screenshotRecordResult{
		Action:         "record",
		FramesCaptured: 12,
		ActualDuration: "1m0s",
		StoppedBy:      "duration",
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed screenshotRecordResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Action != "record" {
		t.Errorf("action: got %q, want %q", parsed.Action, "record")
	}
	if parsed.FramesCaptured != 12 {
		t.Errorf("frames: got %d, want 12", parsed.FramesCaptured)
	}
	if parsed.StoppedBy != "duration" {
		t.Errorf("stopped_by: got %q, want %q", parsed.StoppedBy, "duration")
	}
}

func TestParseScreenshotParams_SingleExplicit(t *testing.T) {
	p, _ := json.Marshal(screenshotParams{Action: "single"})
	task := structs.Task{Params: string(p)}
	params := parseScreenshotParams(task)
	if params.Action != "single" {
		t.Errorf("action: got %q, want %q", params.Action, "single")
	}
}
