//go:build windows

package commands

import (
	"golang.org/x/sys/windows/registry"
)

// securityInfoWindowsNative reads security controls from the Windows registry
// directly — no PowerShell subprocess spawned for registry-readable values.
// Returns controls for: Defender RT, UAC, Firewall profiles.
// Returns nil if registry access fails entirely (caller should fall back).
func securityInfoWindowsNative() []secControl {
	var controls []secControl
	var anySuccess bool

	// Windows Defender real-time protection
	// DisableRealtimeMonitoring: 0 = enabled, 1 = disabled, missing = enabled (default)
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`, registry.READ); err == nil {
		val, _, err := key.GetIntegerValue("DisableRealtimeMonitoring")
		key.Close()
		if err != nil || val == 0 {
			controls = append(controls, secControl{"Windows Defender RT", "enabled", "real-time protection"})
		} else {
			controls = append(controls, secControl{"Windows Defender RT", "disabled", ""})
		}
		anySuccess = true
	}

	// AMSI (always present on Windows 10+)
	controls = append(controls, secControl{"AMSI", "enabled", "default on Windows 10+"})

	// Credential Guard — check DeviceGuard registry
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\DeviceGuard`, registry.READ); err == nil {
		val, _, err := key.GetIntegerValue("EnableVirtualizationBasedSecurity")
		key.Close()
		if err == nil && val == 1 {
			controls = append(controls, secControl{"Credential Guard", "enabled", ""})
		} else {
			controls = append(controls, secControl{"Credential Guard", "disabled", ""})
		}
		anySuccess = true
	}

	// UAC
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.READ); err == nil {
		val, _, err := key.GetIntegerValue("EnableLUA")
		key.Close()
		if err == nil && val == 1 {
			controls = append(controls, secControl{"UAC", "enabled", ""})
		} else {
			controls = append(controls, secControl{"UAC", "disabled", ""})
		}
		anySuccess = true
	}

	// Windows Firewall profiles (Domain, Standard/Private, Public)
	profileNames := []struct {
		regName     string
		displayName string
	}{
		{"DomainProfile", "Domain"},
		{"StandardProfile", "Private"},
		{"PublicProfile", "Public"},
	}
	var fwDetails []string
	for _, p := range profileNames {
		if key, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`+p.regName,
			registry.READ); err == nil {
			val, _, err := key.GetIntegerValue("EnableFirewall")
			key.Close()
			if err == nil {
				if val == 1 {
					fwDetails = append(fwDetails, p.displayName+":True")
				} else {
					fwDetails = append(fwDetails, p.displayName+":False")
				}
			}
			anySuccess = true
		}
	}
	if len(fwDetails) > 0 {
		details := ""
		for i, d := range fwDetails {
			if i > 0 {
				details += " "
			}
			details += d
		}
		controls = append(controls, secControl{"Windows Firewall", "info", details})
	}

	if !anySuccess {
		return nil
	}
	return controls
}
