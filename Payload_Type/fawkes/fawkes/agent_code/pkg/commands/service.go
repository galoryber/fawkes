//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type ServiceCommand struct{}

func (c *ServiceCommand) Name() string {
	return "service"
}

func (c *ServiceCommand) Description() string {
	return "Manage Windows services via SCM API (query, start, stop, create, delete, list)"
}

type serviceArgs struct {
	Action  string `json:"action"`
	Name    string `json:"name"`
	BinPath string `json:"binpath"`
	Display string `json:"display"`
	Start   string `json:"start"`
}

func (c *ServiceCommand) Execute(task structs.Task) structs.CommandResult {
	var args serviceArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required (action, name)",
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

	switch strings.ToLower(args.Action) {
	case "query":
		return serviceQuery(args)
	case "start":
		return serviceStart(args)
	case "stop":
		return serviceStop(args)
	case "create":
		return serviceCreate(args)
	case "delete":
		return serviceDelete(args)
	case "list":
		return serviceList()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: query, start, stop, create, delete, list", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func serviceQuery(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for service query",
			Status:    "error",
			Completed: true,
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to SCM: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer m.Disconnect()

	s, err := m.OpenService(args.Name)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening service '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying service '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}

	config, err := s.Config()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error getting config for '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func serviceStart(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required to start a service",
			Status:    "error",
			Completed: true,
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to SCM: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer m.Disconnect()

	s, err := m.OpenService(args.Name)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening service '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error starting service '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Started service '%s'", args.Name),
		Status:    "success",
		Completed: true,
	}
}

func serviceStop(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required to stop a service",
			Status:    "error",
			Completed: true,
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to SCM: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer m.Disconnect()

	s, err := m.OpenService(args.Name)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening service '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error stopping service '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Stopped service '%s' (state: %s)", args.Name, describeServiceState(status.State)),
		Status:    "success",
		Completed: true,
	}
}

func serviceCreate(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for service creation",
			Status:    "error",
			Completed: true,
		}
	}
	if args.BinPath == "" {
		return structs.CommandResult{
			Output:    "Error: binpath is required for service creation",
			Status:    "error",
			Completed: true,
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to SCM: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating service '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func serviceDelete(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for service deletion",
			Status:    "error",
			Completed: true,
		}
	}

	m, err := mgr.Connect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to SCM: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer m.Disconnect()

	s, err := m.OpenService(args.Name)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening service '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error deleting service '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Deleted service '%s'", args.Name),
		Status:    "success",
		Completed: true,
	}
}

func serviceList() structs.CommandResult {
	m, err := mgr.Connect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to SCM: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer m.Disconnect()

	names, err := m.ListServices()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing services: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Windows Services (%d):\n", len(names)))
	sb.WriteString(fmt.Sprintf("%-40s %-10s %s\n", "Name", "State", "Display Name"))
	sb.WriteString(strings.Repeat("-", 90) + "\n")

	for _, name := range names {
		s, sErr := m.OpenService(name)
		if sErr != nil {
			sb.WriteString(fmt.Sprintf("%-40s %-10s %s\n", name, "(error)", sErr.Error()))
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
		sb.WriteString(fmt.Sprintf("%-40s %-10s %s\n", name, state, displayName))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
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
