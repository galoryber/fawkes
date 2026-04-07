package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

type secInfoParams struct {
	Action string `json:"action"`
}

// SecurityInfoCommand reports security posture and controls.
type SecurityInfoCommand struct{}

func (c *SecurityInfoCommand) Name() string { return "security-info" }
func (c *SecurityInfoCommand) Description() string {
	return "Report security posture and active controls"
}

type secControl struct {
	Name    string
	Status  string // "enabled", "disabled", "not found", "info", "warning"
	Details string
}

func (c *SecurityInfoCommand) Execute(task structs.Task) structs.CommandResult {
	var params secInfoParams
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &params)
	}
	if params.Action == "" {
		params.Action = "all"
	}

	if params.Action == "edr" {
		return securityInfoEDR()
	}

	var controls []secControl

	switch runtime.GOOS {
	case "linux":
		controls = securityInfoLinux()
	case "darwin":
		controls = securityInfoDarwin()
	case "windows":
		controls = securityInfoWindows()
	}

	var sb strings.Builder
	sb.WriteString("[*] Security Posture Report\n\n")
	sb.WriteString(fmt.Sprintf("%-30s %-12s %s\n", "Control", "Status", "Details"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	enabledCount := 0
	for _, ctl := range controls {
		var indicator string
		switch ctl.Status {
		case "enabled":
			indicator = "[+]"
			enabledCount++
		case "disabled":
			indicator = "[-]"
		case "warning":
			indicator = "[!]"
		default:
			indicator = "[?]"
		}
		sb.WriteString(fmt.Sprintf("%s %-27s %-12s %s\n", indicator, ctl.Name, ctl.Status, ctl.Details))
	}

	sb.WriteString(fmt.Sprintf("\n[*] %d/%d security controls active\n", enabledCount, len(controls)))

	return successResult(sb.String())
}


func securityInfoWindows() []secControl {
	// Try native registry reading first (no subprocess spawned for Defender/UAC/Firewall/CredGuard)
	controls := securityInfoWindowsNative()

	// Fall back to PowerShell if native reading failed entirely
	if controls == nil {
		defenderCmd := `(Get-MpComputerStatus).RealTimeProtectionEnabled`
		defender := runQuietCommand("powershell", BuildPSArgs(defenderCmd, InternalPSOptions())...)
		if strings.Contains(strings.TrimSpace(defender), "True") {
			controls = append(controls, secControl{"Windows Defender RT", "enabled", "real-time protection"})
		} else if strings.Contains(strings.TrimSpace(defender), "False") {
			controls = append(controls, secControl{"Windows Defender RT", "disabled", ""})
		}

		controls = append(controls, secControl{"AMSI", "enabled", "default on Windows 10+"})

		credGuardCmd := `(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning`
		credGuard := runQuietCommand("powershell", BuildPSArgs(credGuardCmd, InternalPSOptions())...)
		if strings.Contains(credGuard, "1") || strings.Contains(credGuard, "2") {
			controls = append(controls, secControl{"Credential Guard", "enabled", ""})
		} else {
			controls = append(controls, secControl{"Credential Guard", "disabled", ""})
		}

		uacCmd := `(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA`
		uac := runQuietCommand("powershell", BuildPSArgs(uacCmd, InternalPSOptions())...)
		if strings.TrimSpace(uac) == "1" {
			controls = append(controls, secControl{"UAC", "enabled", ""})
		} else {
			controls = append(controls, secControl{"UAC", "disabled", ""})
		}

		fwCmd := `Get-NetFirewallProfile | ForEach-Object { "$($_.Name):$($_.Enabled)" }`
		fw := runQuietCommand("powershell", BuildPSArgs(fwCmd, InternalPSOptions())...)
		if fw != "" {
			controls = append(controls, secControl{"Windows Firewall", "info", strings.TrimSpace(fw)})
		}
	}

	// BitLocker and PS CLM always require PowerShell (no registry equivalent)
	blCmd := `(Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue).ProtectionStatus`
	bl := runQuietCommand("powershell", BuildPSArgs(blCmd, InternalPSOptions())...)
	if strings.TrimSpace(bl) == "On" {
		controls = append(controls, secControl{"BitLocker (C:)", "enabled", "volume encrypted"})
	} else if strings.TrimSpace(bl) == "Off" {
		controls = append(controls, secControl{"BitLocker (C:)", "disabled", ""})
	}

	clmCmd := `$ExecutionContext.SessionState.LanguageMode`
	clm := runQuietCommand("powershell", BuildPSArgs(clmCmd, InternalPSOptions())...)
	if strings.Contains(clm, "ConstrainedLanguage") {
		controls = append(controls, secControl{"PS Constrained Lang", "enabled", "CLM active"})
	} else if strings.Contains(clm, "FullLanguage") {
		controls = append(controls, secControl{"PS Constrained Lang", "disabled", "FullLanguage mode"})
	}

	return controls
}

// readFileQuiet reads a file and returns content, or empty string on error.
func readFileQuiet(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := string(data)
	structs.ZeroBytes(data)
	return s
}

// parseSshdConfig extracts Port and PermitRootLogin from sshd_config content.
// Returns (port, permitRootLogin) with defaults "22" and "unknown" if not found.
func parseSshdConfig(content string) (port, permitRoot string) {
	port = "22"
	permitRoot = "unknown"
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "permitrootlogin") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				permitRoot = parts[1]
			}
		}
		if strings.HasPrefix(lower, "port") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				port = parts[1]
			}
		}
	}
	return
}
