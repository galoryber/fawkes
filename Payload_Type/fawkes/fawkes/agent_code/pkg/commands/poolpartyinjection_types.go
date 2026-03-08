//go:build windows
// +build windows

// poolpartyinjection_types.go contains Windows API type definitions, constants,
// and NT API procedure declarations used by the PoolParty injection variants.

package commands

import "golang.org/x/sys/windows"

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

// Constants for file/ALPC/job object operations
const (
	// File creation flags
	FILE_FLAG_OVERLAPPED  = 0x40000000
	FILE_ATTRIBUTE_NORMAL = 0x00000080
	CREATE_ALWAYS         = 2
	GENERIC_WRITE         = 0x40000000
	FILE_SHARE_READ       = 0x00000001
	FILE_SHARE_WRITE      = 0x00000002

	// File info class
	FileReplaceCompletionInformation = 61

	// ALPC info class
	AlpcAssociateCompletionPortInformation = 2

	// Job object info class
	JobObjectAssociateCompletionPortInformation = 7
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
	Timer           FULL_TP_TIMER
	Handle          uintptr
	WaitPkt         uintptr
	NextWaitHandle  uintptr
	NextWaitTimeout int64 // LARGE_INTEGER
	Direct          TP_DIRECT
	WaitFlags       uint8
	_               [7]byte // padding
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
	Flags               uint32
	SecurityQos         [12]byte // SECURITY_QUALITY_OF_SERVICE
	MaxMessageLength    uint64
	MemoryBandwidth     uint64
	MaxPoolUsage        uint64
	MaxSectionSize      uint64
	MaxViewSize         uint64
	MaxTotalSectionSize uint64
	DupObjectTypes      uint32
	Reserved            uint32
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
	_              [4]byte // padding for 8-byte alignment
	ClientViewSize uintptr // SIZE_T (union with CallbackId, takes larger size)
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
