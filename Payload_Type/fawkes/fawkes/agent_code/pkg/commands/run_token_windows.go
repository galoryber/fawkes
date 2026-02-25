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
		// No impersonation — use standard exec.Command
		cmd := exec.Command("cmd.exe", "/c", cmdLine)
		output, err := cmd.CombinedOutput()
		return string(output), err
	}

	return runWithToken(token, "cmd.exe /c "+cmdLine)
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
