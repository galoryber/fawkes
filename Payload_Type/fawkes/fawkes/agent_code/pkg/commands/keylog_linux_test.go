//go:build linux

package commands

import (
	"testing"
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
