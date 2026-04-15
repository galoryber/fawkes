//go:build linux

package commands

import "fmt"

// linuxKeyToString converts a Linux keycode to a human-readable string.
func linuxKeyToString(code uint16, shift bool) string {
	// Modifier keys — suppress output
	switch code {
	case 29, 97: // KEY_LEFTCTRL, KEY_RIGHTCTRL
		return ""
	case 56, 100: // KEY_LEFTALT, KEY_RIGHTALT
		return ""
	case 125, 126: // KEY_LEFTMETA, KEY_RIGHTMETA
		return "[SUPER]"
	}

	// Special keys
	switch code {
	case 1:
		return "[ESC]"
	case 14:
		return "[BS]"
	case 15:
		return "[TAB]"
	case 28:
		return "[ENTER]\n"
	case 57:
		return " "
	case 58:
		return "[CAPS]"
	case 103:
		return "[UP]"
	case 108:
		return "[DOWN]"
	case 105:
		return "[LEFT]"
	case 106:
		return "[RIGHT]"
	case 111:
		return "[DEL]"
	case 102:
		return "[HOME]"
	case 107:
		return "[END]"
	case 104:
		return "[PGUP]"
	case 109:
		return "[PGDN]"
	case 110:
		return "[INS]"
	}

	// Function keys: F1=59..F12=88
	if code >= 59 && code <= 70 {
		return fmt.Sprintf("[F%d]", code-58)
	}
	if code == 87 {
		return "[F11]"
	}
	if code == 88 {
		return "[F12]"
	}

	// Number row: KEY_1=2..KEY_0=11
	if code >= 2 && code <= 11 {
		if shift {
			shiftedNum := []string{"!", "@", "#", "$", "%", "^", "&", "*", "(", ")"}
			return shiftedNum[code-2]
		}
		if code == 11 {
			return "0"
		}
		return string(rune('0' + code - 1))
	}

	// Letter keys: KEY_Q=16..KEY_P=25, KEY_A=30..KEY_L=38, KEY_Z=44..KEY_M=50
	letter := linuxCodeToLetter(code)
	if letter != 0 {
		if shift {
			return string(letter - 32) // uppercase
		}
		return string(letter)
	}

	// Punctuation keys
	return linuxCodeToPunct(code, shift)
}

// linuxCodeToLetter maps Linux keycodes to lowercase ASCII letters.
func linuxCodeToLetter(code uint16) byte {
	keyMap := map[uint16]byte{
		16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't',
		21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p',
		30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g',
		35: 'h', 36: 'j', 37: 'k', 38: 'l',
		44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b',
		49: 'n', 50: 'm',
	}
	return keyMap[code]
}

// linuxCodeToPunct maps Linux keycodes to punctuation characters.
func linuxCodeToPunct(code uint16, shift bool) string {
	type punctPair struct {
		normal  string
		shifted string
	}
	punctMap := map[uint16]punctPair{
		12: {"-", "_"},
		13: {"=", "+"},
		26: {"[", "{"},
		27: {"]", "}"},
		39: {";", ":"},
		40: {"'", "\""},
		41: {"`", "~"},
		43: {"\\", "|"},
		51: {",", "<"},
		52: {".", ">"},
		53: {"/", "?"},
	}

	if p, ok := punctMap[code]; ok {
		if shift {
			return p.shifted
		}
		return p.normal
	}

	// Numpad keys
	if code >= 71 && code <= 83 {
		numpad := map[uint16]string{
			71: "7", 72: "8", 73: "9", 74: "-",
			75: "4", 76: "5", 77: "6", 78: "+",
			79: "1", 80: "2", 81: "3",
			82: "0", 83: ".",
		}
		if s, ok := numpad[code]; ok {
			return s
		}
	}

	if code == 55 { // KP_MULTIPLY
		return "*"
	}
	if code == 98 { // KP_DIVIDE
		return "/"
	}
	if code == 96 { // KP_ENTER
		return "[ENTER]\n"
	}

	return ""
}
