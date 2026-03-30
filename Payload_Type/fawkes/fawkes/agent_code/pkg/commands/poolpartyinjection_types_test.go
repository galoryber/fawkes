//go:build windows
// +build windows

package commands

import (
	"testing"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Struct zero-initialization tests
// Verify that all key structs can be zero-initialized without panic.
// ---------------------------------------------------------------------------

func TestPoolPartyStructZeroInit(t *testing.T) {
	tests := []struct {
		name string
		fn   func()
	}{
		{"WORKER_FACTORY_BASIC_INFORMATION", func() { var s WORKER_FACTORY_BASIC_INFORMATION; _ = s }},
		{"PROCESS_HANDLE_TABLE_ENTRY_INFO", func() { var s PROCESS_HANDLE_TABLE_ENTRY_INFO; _ = s }},
		{"PROCESS_HANDLE_SNAPSHOT_INFORMATION", func() { var s PROCESS_HANDLE_SNAPSHOT_INFORMATION; _ = s }},
		{"PUBLIC_OBJECT_TYPE_INFORMATION", func() { var s PUBLIC_OBJECT_TYPE_INFORMATION; _ = s }},
		{"LIST_ENTRY", func() { var s LIST_ENTRY; _ = s }},
		{"TP_TASK_CALLBACKS", func() { var s TP_TASK_CALLBACKS; _ = s }},
		{"TP_TASK", func() { var s TP_TASK; _ = s }},
		{"TP_DIRECT", func() { var s TP_DIRECT; _ = s }},
		{"TPP_WORK_STATE", func() { var s TPP_WORK_STATE; _ = s }},
		{"TPP_CLEANUP_GROUP_MEMBER", func() { var s TPP_CLEANUP_GROUP_MEMBER; _ = s }},
		{"FULL_TP_WORK", func() { var s FULL_TP_WORK; _ = s }},
		{"TPP_QUEUE", func() { var s TPP_QUEUE; _ = s }},
		{"TPP_PH", func() { var s TPP_PH; _ = s }},
		{"TPP_PH_LINKS", func() { var s TPP_PH_LINKS; _ = s }},
		{"TPP_TIMER_SUBQUEUE", func() { var s TPP_TIMER_SUBQUEUE; _ = s }},
		{"TPP_TIMER_QUEUE", func() { var s TPP_TIMER_QUEUE; _ = s }},
		{"FULL_TP_POOL", func() { var s FULL_TP_POOL; _ = s }},
		{"FULL_TP_TIMER", func() { var s FULL_TP_TIMER; _ = s }},
		{"FULL_TP_WAIT", func() { var s FULL_TP_WAIT; _ = s }},
		{"FULL_TP_IO", func() { var s FULL_TP_IO; _ = s }},
		{"FULL_TP_ALPC", func() { var s FULL_TP_ALPC; _ = s }},
		{"FULL_TP_JOB", func() { var s FULL_TP_JOB; _ = s }},
		{"T2_SET_PARAMETERS", func() { var s T2_SET_PARAMETERS; _ = s }},
		{"FILE_COMPLETION_INFORMATION", func() { var s FILE_COMPLETION_INFORMATION; _ = s }},
		{"JOBOBJECT_ASSOCIATE_COMPLETION_PORT", func() { var s JOBOBJECT_ASSOCIATE_COMPLETION_PORT; _ = s }},
		{"ALPC_PORT_ATTRIBUTES", func() { var s ALPC_PORT_ATTRIBUTES; _ = s }},
		{"ALPC_PORT_ASSOCIATE_COMPLETION_PORT", func() { var s ALPC_PORT_ASSOCIATE_COMPLETION_PORT; _ = s }},
		{"PORT_MESSAGE", func() { var s PORT_MESSAGE; _ = s }},
		{"ALPC_MESSAGE", func() { var s ALPC_MESSAGE; _ = s }},
		{"IO_STATUS_BLOCK", func() { var s IO_STATUS_BLOCK; _ = s }},
		{"OBJECT_ATTRIBUTES", func() { var s OBJECT_ATTRIBUTES; _ = s }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn() // should not panic
		})
	}
}

// ---------------------------------------------------------------------------
// Struct size verification tests (x64)
// These sizes must match the Windows API struct layouts on 64-bit systems.
// unsafe.Sizeof reports the Go struct size including padding.
// ---------------------------------------------------------------------------

func TestPoolPartyStructSizes(t *testing.T) {
	ptrSize := unsafe.Sizeof(uintptr(0))
	if ptrSize != 8 {
		t.Skipf("Size tests assume 64-bit (pointer size 8), got %d", ptrSize)
	}

	tests := []struct {
		name     string
		got      uintptr
		expected uintptr
	}{
		// Primitive / small structs
		{"LIST_ENTRY", unsafe.Sizeof(LIST_ENTRY{}), 16},
		{"TP_TASK_CALLBACKS", unsafe.Sizeof(TP_TASK_CALLBACKS{}), 16},
		{"TPP_WORK_STATE", unsafe.Sizeof(TPP_WORK_STATE{}), 4},
		{"TPP_PH", unsafe.Sizeof(TPP_PH{}), 8},
		{"TPP_PH_LINKS", unsafe.Sizeof(TPP_PH_LINKS{}), 40},
		{"IO_STATUS_BLOCK", unsafe.Sizeof(IO_STATUS_BLOCK{}), 16},
		{"FILE_COMPLETION_INFORMATION", unsafe.Sizeof(FILE_COMPLETION_INFORMATION{}), 16},
		{"JOBOBJECT_ASSOCIATE_COMPLETION_PORT", unsafe.Sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT{}), 16},
		{"ALPC_PORT_ASSOCIATE_COMPLETION_PORT", unsafe.Sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT{}), 16},
		{"T2_SET_PARAMETERS", unsafe.Sizeof(T2_SET_PARAMETERS{}), 96},

		// Handle enumeration structs
		{"PROCESS_HANDLE_TABLE_ENTRY_INFO", unsafe.Sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO{}), 40},
		{"PROCESS_HANDLE_SNAPSHOT_INFORMATION", unsafe.Sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION{}), 16},

		// PUBLIC_OBJECT_TYPE_INFORMATION: NTUnicodeString(16) + [22]uint32(88) = 104
		{"PUBLIC_OBJECT_TYPE_INFORMATION", unsafe.Sizeof(PUBLIC_OBJECT_TYPE_INFORMATION{}), 104},

		// Thread pool internal structs
		{"TP_TASK", unsafe.Sizeof(TP_TASK{}), 32},
		{"TP_DIRECT", unsafe.Sizeof(TP_DIRECT{}), 72},
		{"TPP_CLEANUP_GROUP_MEMBER", unsafe.Sizeof(TPP_CLEANUP_GROUP_MEMBER{}), 200},
		{"FULL_TP_WORK", unsafe.Sizeof(FULL_TP_WORK{}), 240},
		{"TPP_QUEUE", unsafe.Sizeof(TPP_QUEUE{}), 24},
		{"TPP_TIMER_SUBQUEUE", unsafe.Sizeof(TPP_TIMER_SUBQUEUE{}), 120},
		{"TPP_TIMER_QUEUE", unsafe.Sizeof(TPP_TIMER_QUEUE{}), 256},

		// WORKER_FACTORY_BASIC_INFORMATION: matches ntdll layout (112 bytes on x64)
		{"WORKER_FACTORY_BASIC_INFORMATION", unsafe.Sizeof(WORKER_FACTORY_BASIC_INFORMATION{}), 112},

		// Complex composite structs
		{"FULL_TP_TIMER", unsafe.Sizeof(FULL_TP_TIMER{}), 360},
		{"FULL_TP_WAIT", unsafe.Sizeof(FULL_TP_WAIT{}), 472},
		{"FULL_TP_IO", unsafe.Sizeof(FULL_TP_IO{}), 288},
		{"FULL_TP_ALPC", unsafe.Sizeof(FULL_TP_ALPC{}), 296},
		{"FULL_TP_JOB", unsafe.Sizeof(FULL_TP_JOB{}), 296},

		// I/O and ALPC structs
		{"PORT_MESSAGE", unsafe.Sizeof(PORT_MESSAGE{}), 40},
		{"ALPC_MESSAGE", unsafe.Sizeof(ALPC_MESSAGE{}), 1040},
		{"ALPC_PORT_ATTRIBUTES", unsafe.Sizeof(ALPC_PORT_ATTRIBUTES{}), 72},
		{"OBJECT_ATTRIBUTES", unsafe.Sizeof(OBJECT_ATTRIBUTES{}), 48},

		// Pool layout (simplified, only fields through TimerQueue)
		{"FULL_TP_POOL", unsafe.Sizeof(FULL_TP_POOL{}), 368},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("sizeof(%s) = %d, want %d", tt.name, tt.got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Field offset tests for structs where exact offset matters for NT API calls
// ---------------------------------------------------------------------------

func TestWorkerFactoryBasicInformationOffsets(t *testing.T) {
	var s WORKER_FACTORY_BASIC_INFORMATION

	// ThreadMinimum is the field we write to when setting minimum threads.
	// It must be at the correct offset for NtSetInformationWorkerFactory.
	offsetThreadMin := unsafe.Offsetof(s.ThreadMinimum)
	// 3 x int64 (24) + 8 x uint8 (8) + uint32 BindingCount (4) = 36
	if offsetThreadMin != 36 {
		t.Errorf("ThreadMinimum offset = %d, want 36", offsetThreadMin)
	}

	offsetStartRoutine := unsafe.Offsetof(s.StartRoutine)
	// After ReleaseCount (uint32 at offset 52 + 4 = 56) + InfiniteWaitGoal (int64 at 56 + 8 = 64)
	if offsetStartRoutine != 64 {
		t.Errorf("StartRoutine offset = %d, want 64", offsetStartRoutine)
	}
}

func TestTPDirectTaskOffset(t *testing.T) {
	var s TP_DIRECT
	// Task must be at offset 0 (it is the first field)
	offsetTask := unsafe.Offsetof(s.Task)
	if offsetTask != 0 {
		t.Errorf("TP_DIRECT.Task offset = %d, want 0", offsetTask)
	}

	// Callback must come after Task(32) + Lock(8) + IoCompletionInformationList(16)
	offsetCallback := unsafe.Offsetof(s.Callback)
	if offsetCallback != 56 {
		t.Errorf("TP_DIRECT.Callback offset = %d, want 56", offsetCallback)
	}
}

func TestFULL_TP_WORKTaskOffset(t *testing.T) {
	var s FULL_TP_WORK
	// Task follows CleanupGroupMember (200 bytes)
	offsetTask := unsafe.Offsetof(s.Task)
	if offsetTask != 200 {
		t.Errorf("FULL_TP_WORK.Task offset = %d, want 200", offsetTask)
	}
}

func TestTPTaskListEntryOffset(t *testing.T) {
	var s TP_TASK
	// ListEntry follows: Callbacks(8) + NumaNode(4) + IdealProcessor(1) + padding(3) = 16
	offsetListEntry := unsafe.Offsetof(s.ListEntry)
	if offsetListEntry != 16 {
		t.Errorf("TP_TASK.ListEntry offset = %d, want 16", offsetListEntry)
	}
}

func TestObjectAttributesSize(t *testing.T) {
	var s OBJECT_ATTRIBUTES
	// Length field must be at offset 0 and should hold the struct size
	offsetLength := unsafe.Offsetof(s.Length)
	if offsetLength != 0 {
		t.Errorf("OBJECT_ATTRIBUTES.Length offset = %d, want 0", offsetLength)
	}
	// RootDirectory at offset 8 (after Length(4) + padding(4))
	offsetRoot := unsafe.Offsetof(s.RootDirectory)
	if offsetRoot != 8 {
		t.Errorf("OBJECT_ATTRIBUTES.RootDirectory offset = %d, want 8", offsetRoot)
	}
}

func TestPortMessageLayout(t *testing.T) {
	var s PORT_MESSAGE
	// ClientViewSize at end: 2*4=8 (headers) + 16 (ClientId) + 4 (MessageId) + 4 (padding) = 32
	offsetClientViewSize := unsafe.Offsetof(s.ClientViewSize)
	if offsetClientViewSize != 32 {
		t.Errorf("PORT_MESSAGE.ClientViewSize offset = %d, want 32", offsetClientViewSize)
	}
}

// ---------------------------------------------------------------------------
// Constant value verification
// ---------------------------------------------------------------------------

func TestPoolPartyConstants(t *testing.T) {
	tests := []struct {
		name     string
		got      uint32
		expected uint32
	}{
		// Process access rights
		{"PROCESS_DUP_HANDLE", PROCESS_DUP_HANDLE, 0x0040},

		// Worker factory individual rights
		{"WORKER_FACTORY_RELEASE_WORKER", WORKER_FACTORY_RELEASE_WORKER, 0x0001},
		{"WORKER_FACTORY_WAIT", WORKER_FACTORY_WAIT, 0x0002},
		{"WORKER_FACTORY_SET_INFORMATION", WORKER_FACTORY_SET_INFORMATION, 0x0004},
		{"WORKER_FACTORY_QUERY_INFORMATION", WORKER_FACTORY_QUERY_INFORMATION, 0x0008},
		{"WORKER_FACTORY_READY_WORKER", WORKER_FACTORY_READY_WORKER, 0x0010},
		{"WORKER_FACTORY_SHUTDOWN", WORKER_FACTORY_SHUTDOWN, 0x0020},

		// WORKER_FACTORY_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED (0x000F0000) | 0x003F
		{"WORKER_FACTORY_ALL_ACCESS", WORKER_FACTORY_ALL_ACCESS, 0x000F003F},

		// I/O Completion access rights
		{"IO_COMPLETION_QUERY_STATE", IO_COMPLETION_QUERY_STATE, 0x0001},
		{"IO_COMPLETION_MODIFY_STATE", IO_COMPLETION_MODIFY_STATE, 0x0002},
		// IO_COMPLETION_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED (0x000F0000) | 0x0003
		{"IO_COMPLETION_ALL_ACCESS", IO_COMPLETION_ALL_ACCESS, 0x000F0003},

		// Worker factory info classes
		{"WorkerFactoryBasicInformation", WorkerFactoryBasicInformation, 7},
		{"WorkerFactoryThreadMinimum", WorkerFactoryThreadMinimum, 4},

		// Process/object info classes
		{"ProcessHandleInformation", ProcessHandleInformation, 51},
		{"ObjectTypeInformation", ObjectTypeInformation, 2},

		// Thread pool callback priorities
		{"TP_CALLBACK_PRIORITY_HIGH", TP_CALLBACK_PRIORITY_HIGH, 0},
		{"TP_CALLBACK_PRIORITY_NORMAL", TP_CALLBACK_PRIORITY_NORMAL, 1},
		{"TP_CALLBACK_PRIORITY_LOW", TP_CALLBACK_PRIORITY_LOW, 2},

		// Memory protection
		{"PAGE_EXECUTE_READWRITE", PAGE_EXECUTE_READWRITE, 0x40},

		// File operations
		{"FILE_FLAG_OVERLAPPED", FILE_FLAG_OVERLAPPED, 0x40000000},
		{"FILE_ATTRIBUTE_NORMAL", FILE_ATTRIBUTE_NORMAL, 0x00000080},
		{"CREATE_ALWAYS", CREATE_ALWAYS, 2},
		{"GENERIC_WRITE", GENERIC_WRITE, 0x40000000},
		{"FILE_SHARE_READ", FILE_SHARE_READ, 0x00000001},
		{"FILE_SHARE_WRITE", FILE_SHARE_WRITE, 0x00000002},

		// Info classes
		{"FileReplaceCompletionInformation", FileReplaceCompletionInformation, 61},
		{"AlpcAssociateCompletionPortInformation", AlpcAssociateCompletionPortInformation, 2},
		{"JobObjectAssociateCompletionPortInformation", JobObjectAssociateCompletionPortInformation, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = 0x%X, want 0x%X", tt.name, tt.got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Verify composite constant relationships
// ---------------------------------------------------------------------------

func TestWorkerFactoryAllAccessComposition(t *testing.T) {
	// ALL_ACCESS should be the OR of STANDARD_RIGHTS_REQUIRED and all individual rights
	individual := uint32(WORKER_FACTORY_RELEASE_WORKER |
		WORKER_FACTORY_WAIT |
		WORKER_FACTORY_SET_INFORMATION |
		WORKER_FACTORY_QUERY_INFORMATION |
		WORKER_FACTORY_READY_WORKER |
		WORKER_FACTORY_SHUTDOWN)

	if individual != 0x3F {
		t.Errorf("Individual worker factory rights OR = 0x%X, want 0x3F", individual)
	}

	// The ALL_ACCESS value should include STANDARD_RIGHTS_REQUIRED (0xF0000)
	if WORKER_FACTORY_ALL_ACCESS&0x000F0000 == 0 {
		t.Error("WORKER_FACTORY_ALL_ACCESS does not include STANDARD_RIGHTS_REQUIRED bits")
	}

	// And should include all individual rights
	if WORKER_FACTORY_ALL_ACCESS&individual != individual {
		t.Error("WORKER_FACTORY_ALL_ACCESS missing individual worker factory rights")
	}
}

func TestIOCompletionAllAccessComposition(t *testing.T) {
	individual := uint32(IO_COMPLETION_QUERY_STATE | IO_COMPLETION_MODIFY_STATE)
	if individual != 0x03 {
		t.Errorf("Individual IO completion rights OR = 0x%X, want 0x03", individual)
	}

	if IO_COMPLETION_ALL_ACCESS&0x000F0000 == 0 {
		t.Error("IO_COMPLETION_ALL_ACCESS does not include STANDARD_RIGHTS_REQUIRED bits")
	}

	if IO_COMPLETION_ALL_ACCESS&individual != individual {
		t.Error("IO_COMPLETION_ALL_ACCESS missing individual IO completion rights")
	}
}

// ---------------------------------------------------------------------------
// Callback priority ordering
// ---------------------------------------------------------------------------

func TestCallbackPriorityOrdering(t *testing.T) {
	// HIGH < NORMAL < LOW (lower number = higher priority)
	if TP_CALLBACK_PRIORITY_HIGH >= TP_CALLBACK_PRIORITY_NORMAL {
		t.Error("HIGH priority should be numerically less than NORMAL")
	}
	if TP_CALLBACK_PRIORITY_NORMAL >= TP_CALLBACK_PRIORITY_LOW {
		t.Error("NORMAL priority should be numerically less than LOW")
	}
}

// ---------------------------------------------------------------------------
// NT API proc variables are initialized (non-nil lazy procs)
// ---------------------------------------------------------------------------

func TestNtAPIProcVariablesExist(t *testing.T) {
	procs := []struct {
		name string
		proc interface{ Find() error }
	}{
		{"NtQueryInformationWorkerFactory", procNtQueryInformationWorkerFactory},
		{"NtSetInformationWorkerFactory", procNtSetInformationWorkerFactory},
		{"NtQueryInformationProcess", procNtQueryInformationProcess},
		{"NtQueryObject", procNtQueryObject},
		{"ZwSetIoCompletion", procZwSetIoCompletion},
		{"RtlNtStatusToDosError", procRtlNtStatusToDosError},
		{"NtSetTimer2", procNtSetTimer2},
		{"ZwAssociateWaitCompletionPacket", procZwAssociateWaitCompletionPacket},
		{"ZwSetInformationFile", procZwSetInformationFile},
		{"NtAlpcCreatePort", procNtAlpcCreatePort},
		{"NtAlpcSetInformation", procNtAlpcSetInformation},
		{"NtAlpcConnectPort", procNtAlpcConnectPort},
		{"TpAllocAlpcCompletion", procTpAllocAlpcCompletion},
		{"TpAllocJobNotification", procTpAllocJobNotification},
	}

	for _, p := range procs {
		t.Run(p.name, func(t *testing.T) {
			if p.proc == nil {
				t.Errorf("proc %s is nil", p.name)
			}
			// LazyProc.Find() resolves the function; it may fail on
			// older Windows versions but the object should not be nil.
		})
	}
}

func TestKernel32ProcVariablesExist(t *testing.T) {
	procs := []struct {
		name string
		proc interface{ Find() error }
	}{
		{"CreateThreadpoolWork", procCreateThreadpoolWork},
		{"CloseThreadpoolWork", procCloseThreadpoolWork},
		{"CreateThreadpoolTimer", procCreateThreadpoolTimer},
		{"CloseThreadpoolTimer", procCloseThreadpoolTimer},
		{"CreateThreadpoolWait", procCreateThreadpoolWait},
		{"CloseThreadpoolWait", procCloseThreadpoolWait},
		{"CreateThreadpoolIo", procCreateThreadpoolIo},
		{"CloseThreadpoolIo", procCloseThreadpoolIo},
		{"CreateEventW", procCreateEventW},
		{"SetEvent", procSetEvent},
		{"CreateFileW", procCreateFileW},
		{"WriteFile", procWriteFile},
		{"CreateJobObjectW", procCreateJobObjectW},
		{"SetInformationJobObject", procSetInformationJobObject},
		{"AssignProcessToJobObject", procAssignProcessToJobObject},
		{"GetCurrentProcess", procGetCurrentProcess},
	}

	for _, p := range procs {
		t.Run(p.name, func(t *testing.T) {
			if p.proc == nil {
				t.Errorf("proc %s is nil", p.name)
			}
		})
	}
}
