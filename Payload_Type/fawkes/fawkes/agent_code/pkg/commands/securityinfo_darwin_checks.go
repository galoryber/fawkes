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

	return controls
}
