//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// TsCommand implements the ts (thread scan) command
type TsCommand struct{}

// Name returns the command name
func (c *TsCommand) Name() string {
	return "ts"
}

// Description returns the command description
func (c *TsCommand) Description() string {
	return "List threads - displays threads in processes, focusing on alertable threads"
}

// TsArgs represents the arguments for ts command
type TsArgs struct {
	All bool  `json:"all"` // Show all threads, not just alertable
	PID int32 `json:"pid"` // Filter to specific process ID
}

// ThreadInfo represents thread information
type ThreadInfo struct {
	ThreadID   uint32
	WaitReason string
}

// ProcessThreadInfo represents a process with its threads
type ProcessThreadInfo struct {
	PID       uint32
	Name      string
	Arch      string
	Owner     string
	Integrity string
	Threads   []ThreadInfo
}

// Windows API constants
const (
	TH32CS_SNAPTHREAD  = 0x00000004
	TH32CS_SNAPPROCESS = 0x00000002

	THREAD_QUERY_INFORMATION         = 0x0040
	THREAD_QUERY_LIMITED_INFORMATION = 0x0800

	// ThreadWaitReason values from Windows
	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationthread
	ThreadBasicInformation = 0
)

// THREADENTRY32 structure for Thread32First/Next
type THREADENTRY32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

// PROCESSENTRY32W structure for Process32First/Next
type PROCESSENTRY32W struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

// THREAD_BASIC_INFORMATION from ntdll
type THREAD_BASIC_INFORMATION struct {
	ExitStatus     uint32
	TebBaseAddress uintptr
	ClientId       CLIENT_ID
	AffinityMask   uintptr
	Priority       int32
	BasePriority   int32
}

type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

// KWAIT_REASON enumeration - thread wait reasons
// Values from Windows SDK / ntddk.h
type KWAIT_REASON uint32

const (
	Executive         KWAIT_REASON = 0
	FreePage          KWAIT_REASON = 1
	PageIn            KWAIT_REASON = 2
	PoolAllocation    KWAIT_REASON = 3
	DelayExecution    KWAIT_REASON = 4 // Alertable - SleepEx, WaitForSingleObjectEx, etc.
	Suspended         KWAIT_REASON = 5 // Alertable - Thread is suspended
	UserRequest       KWAIT_REASON = 6
	WrExecutive       KWAIT_REASON = 7
	WrFreePage        KWAIT_REASON = 8
	WrPageIn          KWAIT_REASON = 9
	WrPoolAllocation  KWAIT_REASON = 10
	WrDelayExecution  KWAIT_REASON = 11
	WrSuspended       KWAIT_REASON = 12
	WrUserRequest     KWAIT_REASON = 13
	WrEventPair       KWAIT_REASON = 14
	WrQueue           KWAIT_REASON = 15
	WrLpcReceive      KWAIT_REASON = 16
	WrLpcReply        KWAIT_REASON = 17
	WrVirtualMemory   KWAIT_REASON = 18
	WrPageOut         KWAIT_REASON = 19
	WrRendezvous      KWAIT_REASON = 20
	WrKeyedEvent      KWAIT_REASON = 21
	WrTerminated      KWAIT_REASON = 22
	WrProcessInSwap   KWAIT_REASON = 23
	WrCpuRateControl  KWAIT_REASON = 24
	WrCalloutStack    KWAIT_REASON = 25
	WrKernel          KWAIT_REASON = 26
	WrResource        KWAIT_REASON = 27
	WrPushLock        KWAIT_REASON = 28
	WrMutex           KWAIT_REASON = 29
	WrQuantumEnd      KWAIT_REASON = 30
	WrDispatchInt     KWAIT_REASON = 31
	WrPreempted       KWAIT_REASON = 32
	WrYieldExecution  KWAIT_REASON = 33
	WrFastMutex       KWAIT_REASON = 34
	WrGuardedMutex    KWAIT_REASON = 35
	WrRundown         KWAIT_REASON = 36
	WrAlertByThreadId KWAIT_REASON = 37
	WrDeferredPreempt KWAIT_REASON = 38
	MaximumWaitReason KWAIT_REASON = 39
)

// SYSTEM_THREAD_INFORMATION for NtQuerySystemInformation
type SYSTEM_THREAD_INFORMATION struct {
	KernelTime      int64
	UserTime        int64
	CreateTime      int64
	WaitTime        uint32
	StartAddress    uintptr
	ClientId        CLIENT_ID
	Priority        int32
	BasePriority    int32
	ContextSwitches uint32
	ThreadState     uint32
	WaitReason      KWAIT_REASON
}

// Windows API procedures
var (
	kernel32DLL                  = windows.NewLazySystemDLL("kernel32.dll")
	ntdllDLL                     = windows.NewLazySystemDLL("ntdll.dll")
	advapi32DLL                  = windows.NewLazySystemDLL("advapi32.dll")
	procCreateToolhelp32Snapshot = kernel32DLL.NewProc("CreateToolhelp32Snapshot")
	procThread32First            = kernel32DLL.NewProc("Thread32First")
	procThread32Next             = kernel32DLL.NewProc("Thread32Next")
	procProcess32FirstW          = kernel32DLL.NewProc("Process32FirstW")
	procProcess32NextW           = kernel32DLL.NewProc("Process32NextW")
	procIsWow64Process           = kernel32DLL.NewProc("IsWow64Process")
	procNtQuerySystemInformation = ntdllDLL.NewProc("NtQuerySystemInformation")
	procGetSidSubAuthorityCount  = advapi32DLL.NewProc("GetSidSubAuthorityCount")
	procGetSidSubAuthority       = advapi32DLL.NewProc("GetSidSubAuthority")
)

// Integrity level constants
const (
	SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000
	SECURITY_MANDATORY_LOW_RID       = 0x00001000
	SECURITY_MANDATORY_MEDIUM_RID    = 0x00002000
	SECURITY_MANDATORY_HIGH_RID      = 0x00003000
	SECURITY_MANDATORY_SYSTEM_RID    = 0x00004000
)

// SystemProcessInformation constant for NtQuerySystemInformation
const SystemProcessInformation = 5

// SYSTEM_PROCESS_INFORMATION structure
type SYSTEM_PROCESS_INFORMATION struct {
	NextEntryOffset              uint32
	NumberOfThreads              uint32
	WorkingSetPrivateSize        int64
	HardFaultCount               uint32
	NumberOfThreadsHighWatermark uint32
	CycleTime                    uint64
	CreateTime                   int64
	UserTime                     int64
	KernelTime                   int64
	ImageName                    UNICODE_STRING
	BasePriority                 int32
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
	HandleCount                  uint32
	SessionId                    uint32
	UniqueProcessKey             uintptr
	PeakVirtualSize              uintptr
	VirtualSize                  uintptr
	PageFaultCount               uint32
	PeakWorkingSetSize           uintptr
	WorkingSetSize               uintptr
	QuotaPeakPagedPoolUsage      uintptr
	QuotaPagedPoolUsage          uintptr
	QuotaPeakNonPagedPoolUsage   uintptr
	QuotaNonPagedPoolUsage       uintptr
	PagefileUsage                uintptr
	PeakPagefileUsage            uintptr
	PrivatePageCount             uintptr
	ReadOperationCount           int64
	WriteOperationCount          int64
	OtherOperationCount          int64
	ReadTransferCount            int64
	WriteTransferCount           int64
	OtherTransferCount           int64
	// Threads array follows immediately after this structure
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// Execute executes the ts command
func (c *TsCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse arguments
	args := TsArgs{}

	if task.Params != "" {
		// Try to parse as JSON first
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			// Parse command line arguments
			parts := strings.Fields(task.Params)
			for i := 0; i < len(parts); i++ {
				switch parts[i] {
				case "-a":
					args.All = true
				case "-i":
					if i+1 < len(parts) {
						if pid, err := strconv.ParseInt(parts[i+1], 10, 32); err == nil {
							args.PID = int32(pid)
						}
						i++
					}
				}
			}
		}
	}

	// Get thread information
	output, err := getThreadInfo(args.All, args.PID)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing threads: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// getThreadInfo enumerates threads using NtQuerySystemInformation
func getThreadInfo(showAll bool, filterPID int32) (string, error) {
	// First, get a map of process names by PID
	processNames := getProcessNames()

	// Use NtQuerySystemInformation to get thread information with wait reasons
	var bufferSize uint32 = 1024 * 1024 // Start with 1MB
	var buffer []byte
	var returnLength uint32

	for {
		buffer = make([]byte, bufferSize)
		ret, _, _ := procNtQuerySystemInformation.Call(
			uintptr(SystemProcessInformation),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(bufferSize),
			uintptr(unsafe.Pointer(&returnLength)),
		)

		// STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
		if ret == 0xC0000004 {
			bufferSize = returnLength + 65536 // Add some extra space
			continue
		}

		if ret != 0 {
			return "", fmt.Errorf("NtQuerySystemInformation failed with status: 0x%X", ret)
		}
		break
	}

	// Parse the results
	var result strings.Builder
	var totalThreads int
	var totalProcesses int

	offset := uint32(0)
	for {
		if offset >= uint32(len(buffer)) {
			break
		}

		procInfo := (*SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset]))

		pid := uint32(procInfo.UniqueProcessId)

		// Apply PID filter if specified
		if filterPID > 0 && int32(pid) != filterPID {
			if procInfo.NextEntryOffset == 0 {
				break
			}
			offset += procInfo.NextEntryOffset
			continue
		}

		// Skip System Idle Process (PID 0)
		if pid == 0 {
			if procInfo.NextEntryOffset == 0 {
				break
			}
			offset += procInfo.NextEntryOffset
			continue
		}

		// Get process name
		procName := "Unknown"
		if procInfo.ImageName.Buffer != nil && procInfo.ImageName.Length > 0 {
			procName = windows.UTF16PtrToString(procInfo.ImageName.Buffer)
		} else if name, ok := processNames[pid]; ok {
			procName = name
		}

		// Get process architecture, owner, and integrity
		arch := getProcessArch(pid)
		owner := getProcessOwner(pid)
		integrity := getProcessIntegrity(pid)

		// Skip low integrity processes when showing alertable only
		if !showAll && (integrity == "Untrusted" || integrity == "Low") {
			if procInfo.NextEntryOffset == 0 {
				break
			}
			offset += procInfo.NextEntryOffset
			continue
		}

		// Get threads for this process
		var matchingThreads []ThreadInfo
		threadOffset := offset + uint32(unsafe.Sizeof(SYSTEM_PROCESS_INFORMATION{}))

		for i := uint32(0); i < procInfo.NumberOfThreads; i++ {
			if threadOffset >= uint32(len(buffer)) {
				break
			}

			threadInfo := (*SYSTEM_THREAD_INFORMATION)(unsafe.Pointer(&buffer[threadOffset]))
			waitReason := threadInfo.WaitReason
			waitReasonStr := getWaitReasonString(waitReason)

			// Check if this is an alertable thread
			isAlertable := waitReason == DelayExecution || waitReason == Suspended ||
				waitReason == WrDelayExecution || waitReason == WrSuspended

			if showAll || isAlertable {
				matchingThreads = append(matchingThreads, ThreadInfo{
					ThreadID:   uint32(threadInfo.ClientId.UniqueThread),
					WaitReason: waitReasonStr,
				})
			}

			threadOffset += uint32(unsafe.Sizeof(SYSTEM_THREAD_INFORMATION{}))
		}

		// Only output if we have matching threads
		if len(matchingThreads) > 0 {
			// Format: [+] Process: PID | Arch | Owner | Integrity | Name
			result.WriteString(fmt.Sprintf("[+] Process: %-6d | %-3s | %-18s | %-10s | %s\n",
				pid, arch, truncateOwner(owner, 18), integrity, procName))

			for _, thread := range matchingThreads {
				result.WriteString(fmt.Sprintf("        Thread: %-6d -> %s\n",
					thread.ThreadID, thread.WaitReason))
			}
			result.WriteString("\n")

			totalThreads += len(matchingThreads)
			totalProcesses++
		}

		if procInfo.NextEntryOffset == 0 {
			break
		}
		offset += procInfo.NextEntryOffset
	}

	if totalProcesses == 0 {
		if showAll {
			return "No accessible processes found", nil
		}
		return "No processes with alertable threads found", nil
	}

	result.WriteString(fmt.Sprintf("Total: %d threads in %d processes\n", totalThreads, totalProcesses))
	return result.String(), nil
}

// getProcessNames returns a map of process names by PID using toolhelp32 snapshot
func getProcessNames() map[uint32]string {
	names := make(map[uint32]string)

	snapshot, _, err := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot == uintptr(windows.InvalidHandle) {
		return names
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var entry PROCESSENTRY32W
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return names
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		names[entry.ProcessID] = name

		ret, _, err = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			break
		}
	}

	return names
}

// getProcessArch determines if a process is 32-bit or 64-bit
func getProcessArch(pid uint32) string {
	// Default to x64 on 64-bit systems
	arch := "x64"

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return arch
	}
	defer windows.CloseHandle(handle)

	var isWow64 bool
	ret, _, _ := procIsWow64Process.Call(uintptr(handle), uintptr(unsafe.Pointer(&isWow64)))
	if ret != 0 && isWow64 {
		arch = "x86"
	}

	return arch
}

// getProcessOwner returns the owner of a process in DOMAIN\user format
func getProcessOwner(pid uint32) string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "Access Denied"
	}
	defer windows.CloseHandle(handle)

	var token windows.Token
	err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return "Access Denied"
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "Unknown"
	}

	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return "Unknown"
	}

	return fmt.Sprintf("%s\\%s", domain, account)
}

// getProcessIntegrity returns the integrity level of a process
func getProcessIntegrity(pid uint32) string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "Access Denied"
	}
	defer windows.CloseHandle(handle)

	var token windows.Token
	err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return "Access Denied"
	}
	defer token.Close()

	// Check for SYSTEM first
	tokenUser, err := token.GetTokenUser()
	if err == nil {
		systemSID, _ := windows.StringToSid("S-1-5-18")
		if tokenUser.User.Sid.Equals(systemSID) {
			return "System"
		}
	}

	// Get token integrity level
	var size uint32
	windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &size)
	if size == 0 {
		return "Unknown"
	}

	buffer := make([]byte, size)
	err = windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buffer[0], size, &size)
	if err != nil {
		return "Unknown"
	}

	// Parse TOKEN_MANDATORY_LABEL
	tml := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buffer[0]))
	sid := tml.Label.Sid

	// Get the RID (last subauthority) using advapi32 calls
	subAuthCountPtr, _, _ := procGetSidSubAuthorityCount.Call(uintptr(unsafe.Pointer(sid)))
	if subAuthCountPtr == 0 {
		return "Unknown"
	}
	subAuthCount := *(*uint8)(unsafe.Pointer(subAuthCountPtr))
	if subAuthCount == 0 {
		return "Unknown"
	}

	ridPtr, _, _ := procGetSidSubAuthority.Call(
		uintptr(unsafe.Pointer(sid)),
		uintptr(subAuthCount-1),
	)
	if ridPtr == 0 {
		return "Unknown"
	}
	rid := *(*uint32)(unsafe.Pointer(ridPtr))

	switch {
	case rid < SECURITY_MANDATORY_LOW_RID:
		return "Untrusted"
	case rid < SECURITY_MANDATORY_MEDIUM_RID:
		return "Low"
	case rid < SECURITY_MANDATORY_HIGH_RID:
		return "Medium"
	case rid < SECURITY_MANDATORY_SYSTEM_RID:
		return "High"
	default:
		return "System"
	}
}

// getWaitReasonString converts a wait reason enum to string
func getWaitReasonString(reason KWAIT_REASON) string {
	return tsWaitReasonString(uint32(reason))
}

// truncateOwner truncates owner string to max length
func truncateOwner(owner string, maxLen int) string {
	return tsTruncateOwner(owner, maxLen)
}
