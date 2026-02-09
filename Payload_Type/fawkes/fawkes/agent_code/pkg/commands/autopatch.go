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

	output, err := PerformAutoPatch(args.DllName, args.FunctionName, args.NumBytes)
	if err != nil {
		return structs.CommandResult{
			Output:    err.Error(),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// PerformAutoPatch applies a jump-to-ret patch on the specified function.
// It loads the target DLL, finds the function, searches for the nearest C3 (RET)
// instruction, and writes a JMP to it at the function prologue.
// This is exported so that other commands (e.g., start-clr) can reuse it.
func PerformAutoPatch(dllName, functionName string, numBytes int) (string, error) {
	// Load DLL
	dll, err := syscall.LoadDLL(dllName)
	if err != nil {
		return "", fmt.Errorf("error loading DLL %s: %v", dllName, err)
	}

	// Get function address
	proc, err := dll.FindProc(functionName)
	if err != nil {
		return "", fmt.Errorf("error finding function %s: %v", functionName, err)
	}

	functionAddress := proc.Addr()

	// Calculate buffer size (read backwards and forwards)
	bufferSize := numBytes * 2
	buffer := make([]byte, bufferSize)

	// Read memory around the function address
	k32 := syscall.MustLoadDLL("kernel32.dll")
	readProcessMemory := k32.MustFindProc("ReadProcessMemory")

	currentProcess, _ := syscall.GetCurrentProcess()
	var bytesRead uintptr

	// Read from (functionAddress - numBytes) forward
	targetAddress := uintptr(functionAddress) - uintptr(numBytes)

	ret, _, err := readProcessMemory.Call(
		uintptr(currentProcess),
		targetAddress,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	if ret == 0 {
		return "", fmt.Errorf("error reading memory: %v", err)
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
		return "", fmt.Errorf("no C3 (return) instruction found in search range")
	}

	// Calculate offset for JMP instruction relative to function address
	offset := c3Index - numBytes

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
	writeProcessMemory := k32.MustFindProc("WriteProcessMemory")
	var bytesWritten uintptr

	ret, _, err = writeProcessMemory.Call(
		uintptr(currentProcess),
		uintptr(functionAddress),
		uintptr(unsafe.Pointer(&jumpOp[0])),
		uintptr(len(jumpOp)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if ret == 0 {
		return "", fmt.Errorf("error writing jump instruction: %v", err)
	}

	c3Address := targetAddress + uintptr(c3Index)

	output := fmt.Sprintf("AutoPatch applied successfully!\n")
	output += fmt.Sprintf("Function: %s!%s at 0x%x\n", dllName, functionName, functionAddress)
	output += fmt.Sprintf("Found C3 at offset %d (0x%x)\n", offset, c3Address)
	output += fmt.Sprintf("Applied %s JMP (%d bytes)\n", jumpType, len(jumpOp))
	output += fmt.Sprintf("Jump bytes: %X", jumpOp)

	return output, nil
}
