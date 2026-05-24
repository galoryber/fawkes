package commands

import (
	"fmt"
	"os"
	"strings"
)

func securityInfoDarwin() []secControl {
	var controls []secControl

	// System Integrity Protection (SIP)
	csrutil := runQuietCommand("csrutil", "status")
	if strings.Contains(csrutil, "enabled") {
		controls = append(controls, secControl{"SIP (csrutil)", "enabled", ""})
	} else if strings.Contains(csrutil, "disabled") {
		controls = append(controls, secControl{"SIP (csrutil)", "disabled", ""})
	} else {
		controls = append(controls, secControl{"SIP (csrutil)", "info", strings.TrimSpace(csrutil)})
	}

	// Gatekeeper
	spctl := runQuietCommand("spctl", "--status")
	if strings.Contains(spctl, "enabled") {
		controls = append(controls, secControl{"Gatekeeper", "enabled", ""})
	} else if strings.Contains(spctl, "disabled") {
		controls = append(controls, secControl{"Gatekeeper", "disabled", ""})
	}

	// FileVault
	fdesetup := runQuietCommand("fdesetup", "status")
	if strings.Contains(fdesetup, "On") {
		controls = append(controls, secControl{"FileVault", "enabled", "full disk encryption"})
	} else if strings.Contains(fdesetup, "Off") {
		controls = append(controls, secControl{"FileVault", "disabled", ""})
	}

	// Firewall
	fwCheck := runQuietCommand("defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate")
	if strings.TrimSpace(fwCheck) != "0" && fwCheck != "" {
		controls = append(controls, secControl{"macOS Firewall", "enabled", "globalstate=" + strings.TrimSpace(fwCheck)})
	} else {
		controls = append(controls, secControl{"macOS Firewall", "disabled", ""})
	}

	// XProtect — check for XProtect definition files (no subprocess)
	if _, err := os.Stat("/Library/Apple/System/Library/CoreServices/XProtect.bundle"); err == nil {
		controls = append(controls, secControl{"XProtect", "enabled", "definition bundle present"})
	} else if _, err := os.Stat("/System/Library/CoreServices/XProtect.bundle"); err == nil {
		controls = append(controls, secControl{"XProtect", "enabled", "definition bundle present (legacy path)"})
	}

	// --- Native file-read checks (no subprocess) ---

	// MDM / Configuration Profiles — check for managed device
	if entries, err := os.ReadDir("/var/db/ConfigurationProfiles"); err == nil {
		profileCount := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".plist") || strings.HasSuffix(e.Name(), ".mobileconfig") {
				profileCount++
			}
		}
		if profileCount > 0 {
			controls = append(controls, secControl{"Configuration Profiles", "enabled",
				fmt.Sprintf("%d profile(s) installed (managed device)", profileCount)})
		}
	}
	// Also check for MDM enrollment indicator
	if _, err := os.Stat("/var/db/ConfigurationProfiles/Settings/.profilesAreInstalled"); err == nil {
		controls = append(controls, secControl{"MDM Enrollment", "enabled", "device enrolled in MDM"})
	}

	// Remote Login (SSH) — check sshd_config natively
	if sshConfig := readFileQuiet("/etc/ssh/sshd_config"); sshConfig != "" {
		port, permitRoot := parseSshdConfig(sshConfig)
		controls = append(controls, secControl{"Remote Login (SSH)", "enabled",
			fmt.Sprintf("port %s, PermitRootLogin=%s", port, permitRoot)})
	}

	// TCC Database readability — quick probe for Full Disk Access
	tccSystemDB := "/Library/Application Support/com.apple.TCC/TCC.db"
	if f, err := os.Open(tccSystemDB); err == nil {
		f.Close()
		controls = append(controls, secControl{"TCC System DB", "warning", "readable (FDA or root — can enumerate privacy grants)"})
	} else {
		controls = append(controls, secControl{"TCC System DB", "enabled", "protected (not readable without FDA)"})
	}

	// JAMF management detection
	if _, err := os.Stat("/usr/local/jamf/bin/jamf"); err == nil {
		controls = append(controls, secControl{"JAMF (Casper)", "enabled", "enterprise management agent installed"})
	}

	// Apple Remote Desktop — check for ARD agent
	if _, err := os.Stat("/System/Library/CoreServices/RemoteManagement/ARDAgent.app"); err == nil {
		ardPlist := readFileQuiet("/Library/Preferences/com.apple.RemoteDesktop.plist")
		if ardPlist != "" {
			controls = append(controls, secControl{"Remote Desktop (ARD)", "enabled", "agent present with config"})
		} else {
			controls = append(controls, secControl{"Remote Desktop (ARD)", "info", "agent present (config unreadable)"})
		}
	}

	// Endpoint Security framework — detect ES clients (macOS 10.15+)
	controls = append(controls, checkEndpointSecurity()...)

	return controls
}

// checkEndpointSecurity detects macOS Endpoint Security framework consumers
// and System Extensions that use ES for runtime monitoring.
func checkEndpointSecurity() []secControl {
	var controls []secControl

	// Check for System Extensions (ES clients register as system extensions)
	sysExtDir := "/Library/SystemExtensions"
	if entries, err := os.ReadDir(sysExtDir); err == nil {
		var extensions []string
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				extensions = append(extensions, e.Name())
			}
		}
		if len(extensions) > 0 {
			controls = append(controls, secControl{"System Extensions", "enabled",
				fmt.Sprintf("%d extension(s): %s", len(extensions), strings.Join(extensions, ", "))})
		}
	}

	// Probe systemextensionsctl for active extension list
	sysExtList := runQuietCommand("systemextensionsctl", "list")
	if sysExtList != "" {
		activeCount := 0
		for _, line := range strings.Split(sysExtList, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "activated enabled") || strings.Contains(line, "[activated") {
				activeCount++
			}
		}
		if activeCount > 0 {
			controls = append(controls, secControl{"Active System Extensions", "warning",
				fmt.Sprintf("%d activated extension(s) — may include ES clients", activeCount)})
		}
	}

	// Known Endpoint Security framework consumers (detect by bundle/path)
	esClients := []struct {
		name   string
		paths  []string
		detail string
	}{
		{"CrowdStrike Falcon", []string{
			"/Library/CS/falcond",
			"/Applications/Falcon.app",
			"/Library/SystemExtensions/com.crowdstrike.falcon.Agent.systemextension",
		}, "ES client (process, file, network monitoring)"},
		{"SentinelOne", []string{
			"/Library/Sentinel/sentinel-agent.bundle",
			"/opt/sentinelone/bin/sentineld",
		}, "ES client (behavioral AI detection)"},
		{"Microsoft Defender", []string{
			"/Library/Application Support/Microsoft/Defender",
			"/Applications/Microsoft Defender.app",
		}, "ES client (antivirus + EDR)"},
		{"Cortex XDR", []string{
			"/Library/Application Support/PaloAltoNetworks/Traps",
			"/Applications/Cortex XDR.app",
		}, "ES client (endpoint protection)"},
		{"Carbon Black", []string{
			"/Applications/VMware Carbon Black Cloud/CbDefense.app",
			"/Library/Application Support/com.vmware.carbonblack.cloud",
		}, "ES client (behavioral detection)"},
		{"Sophos", []string{
			"/Library/Sophos Anti-Virus",
			"/Applications/Sophos/Sophos Endpoint.app",
		}, "ES client (endpoint protection)"},
		{"ESET Endpoint Security", []string{
			"/Applications/ESET Endpoint Security.app",
			"/Library/Application Support/com.eset.remoteadministrator.agent",
		}, "ES client (antivirus + IDS)"},
		{"Jamf Protect", []string{
			"/usr/local/jamf/bin/jamf-protect",
			"/Library/Application Support/JamfProtect",
		}, "ES client (Apple-focused threat prevention)"},
		{"Kandji", []string{
			"/Library/Kandji/Kandji Agent.app",
		}, "MDM with ES monitoring"},
		{"Mosyle", []string{
			"/Library/Application Support/Mosyle",
		}, "MDM with security extensions"},
	}

	foundES := false
	for _, client := range esClients {
		for _, path := range client.paths {
			if _, err := os.Stat(path); err == nil {
				controls = append(controls, secControl{"ES Client: " + client.name, "warning", client.detail})
				foundES = true
				break
			}
		}
	}

	// Check for Network Extensions (NEFilterDataProvider, DNS proxy)
	neConfigDir := "/Library/Application Support/com.apple.networkextension"
	if _, err := os.Stat(neConfigDir); err == nil {
		controls = append(controls, secControl{"Network Extensions", "enabled", "NEFilterDataProvider or DNS proxy configured"})
	}

	if !foundES {
		controls = append(controls, secControl{"Endpoint Security", "not found", "no ES framework clients detected"})
	}

	return controls
}
