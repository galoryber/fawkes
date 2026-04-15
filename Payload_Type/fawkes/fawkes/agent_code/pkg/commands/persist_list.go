//go:build windows
// +build windows

// persist_list.go implements the "list" method for the persist command.
// Enumerates all known persistence locations: Run keys, startup folder,
// COM hijacking, IFEO, Winlogon, print processors, accessibility features,
// Active Setup, time providers, port monitors, and screensaver.

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// listPersistence lists known persistence entries across all supported vectors.
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

	// Check Active Setup
	lines = append(lines, "--- Active Setup (HKLM\\...\\Active Setup\\Installed Components) ---")
	activeSetupBase := `SOFTWARE\Microsoft\Active Setup\Installed Components`
	asKey, err := registry.OpenKey(registry.LOCAL_MACHINE, activeSetupBase, registry.ENUMERATE_SUB_KEYS)
	asFound := false
	if err == nil {
		asNames, _ := asKey.ReadSubKeyNames(-1)
		asKey.Close()
		for _, name := range asNames {
			subPath := activeSetupBase + `\` + name
			subKey, err := registry.OpenKey(registry.LOCAL_MACHINE, subPath, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			stubPath, _, err := subKey.GetStringValue("StubPath")
			subKey.Close()
			if err == nil && stubPath != "" {
				// Only show non-Microsoft entries (likely persistence)
				if !strings.Contains(strings.ToLower(stubPath), "windows") &&
					!strings.Contains(strings.ToLower(stubPath), "microsoft") {
					displayName := name
					if dKey, err := registry.OpenKey(registry.LOCAL_MACHINE, subPath, registry.QUERY_VALUE); err == nil {
						if dn, _, err := dKey.GetStringValue(""); err == nil && dn != "" {
							displayName = dn
						}
						dKey.Close()
					}
					lines = append(lines, fmt.Sprintf("  %s  %s → %s", name, displayName, stubPath))
					asFound = true
				}
			}
		}
	}
	if !asFound {
		lines = append(lines, "  (no non-Microsoft entries detected)")
	}
	lines = append(lines, "")

	// Check Time Providers
	lines = append(lines, "--- Time Providers (HKLM\\...\\W32Time\\TimeProviders) ---")
	tpKey, err := registry.OpenKey(registry.LOCAL_MACHINE, timeProviderRegBase, registry.ENUMERATE_SUB_KEYS)
	tpFound := false
	if err == nil {
		tpNames, _ := tpKey.ReadSubKeyNames(-1)
		tpKey.Close()
		// Known legitimate providers
		legitimate := map[string]bool{"NtpClient": true, "NtpServer": true, "VMICTimeProvider": true}
		for _, tpName := range tpNames {
			if legitimate[tpName] {
				continue
			}
			subPath := timeProviderRegBase + `\` + tpName
			subKey, err := registry.OpenKey(registry.LOCAL_MACHINE, subPath, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			dllName, _, err := subKey.GetStringValue("DllName")
			enabled, _, _ := subKey.GetIntegerValue("Enabled")
			subKey.Close()
			if err == nil && dllName != "" {
				status := "disabled"
				if enabled == 1 {
					status = "enabled"
				}
				lines = append(lines, fmt.Sprintf("  ⚠ %s → %s (%s)", tpName, dllName, status))
				tpFound = true
			}
		}
	}
	if !tpFound {
		lines = append(lines, "  (no non-standard providers detected)")
	}
	lines = append(lines, "")

	// Check Port Monitors
	lines = append(lines, "--- Port Monitors (HKLM\\...\\Print\\Monitors) ---")
	pmKey, err := registry.OpenKey(registry.LOCAL_MACHINE, portMonitorRegBase, registry.ENUMERATE_SUB_KEYS)
	pmFound := false
	if err == nil {
		pmNames, _ := pmKey.ReadSubKeyNames(-1)
		pmKey.Close()
		// Known legitimate monitors
		legitimatePM := map[string]bool{
			"Local Port":              true,
			"Standard TCP/IP Port":    true,
			"USB Monitor":             true,
			"WSD Port":                true,
			"Microsoft Shared Fax Monitor": true,
		}
		for _, pmName := range pmNames {
			if legitimatePM[pmName] {
				continue
			}
			subPath := portMonitorRegBase + `\` + pmName
			subKey, err := registry.OpenKey(registry.LOCAL_MACHINE, subPath, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			driver, _, err := subKey.GetStringValue("Driver")
			subKey.Close()
			if err == nil && driver != "" {
				lines = append(lines, fmt.Sprintf("  ⚠ %s → %s", pmName, driver))
				pmFound = true
			}
		}
	}
	if !pmFound {
		lines = append(lines, "  (no non-standard monitors detected)")
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

// enumRunKey reads all value names from a Run key under the specified hive.
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
