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

// ReadMemoryCommand implements the read-memory command
type ReadMemoryCommand struct{}

// Name returns the command name
func (c *ReadMemoryCommand) Name() string {
	return "read-memory"
}

// Description returns the command description
func (c *ReadMemoryCommand) Description() string {
	return "Read bytes from a DLL function address"
}

// ReadMemoryArgs represents the arguments for read-memory command
type ReadMemoryArgs struct {
	DllName      string `json:"dll_name"`
	FunctionName string `json:"function_name"`
	StartIndex   int    `json:"start_index"`
	NumBytes     int    `json:"num_bytes"`
}

// Execute executes the read-memory command
func (c *ReadMemoryCommand) Execute(task structs.Task) structs.CommandResult {
	var args ReadMemoryArgs

	// Parse arguments
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Try parsing as space-separated string
		parts := strings.Fields(task.Params)
		if len(parts) != 4 {
			return structs.CommandResult{
				Output:    "Error: Invalid arguments. Usage: read-memory <dll_name> <function_name> <start_index> <num_bytes>",
				Status:    "error",
				Completed: true,
			}
		}
		args.DllName = parts[0]
		args.FunctionName = parts[1]
		fmt.Sscanf(parts[2], "%d", &args.StartIndex)
		fmt.Sscanf(parts[3], "%d", &args.NumBytes)
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

	// Read memory
	buffer := make([]byte, args.NumBytes)
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	readProcessMemory := kernel32.MustFindProc("ReadProcessMemory")
	
	currentProcess, _ := syscall.GetCurrentProcess()
	var bytesRead uintptr
	
	ret, _, err := readProcessMemory.Call(
		uintptr(currentProcess),
		targetAddress,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(args.NumBytes),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading memory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Format output
	hexOutput := make([]string, bytesRead)
	simpleHex := hex.EncodeToString(buffer[:bytesRead])
	
	for i := 0; i < int(bytesRead); i++ {
		hexOutput[i] = fmt.Sprintf("\\x%02X", buffer[i])
	}

	output := fmt.Sprintf("Read %d bytes from %s!%s+0x%x (0x%x):\n", 
		bytesRead, args.DllName, args.FunctionName, args.StartIndex, targetAddress)
	output += fmt.Sprintf("Bytes in \\x format: %s\n", strings.Join(hexOutput, ""))
	output += fmt.Sprintf("Bytes in hex format: %s\n", simpleHex)

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}
