//go:build windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// persistEnumRegistry checks Run/RunOnce keys in HKLM and HKCU.
func persistEnumRegistry(sb *strings.Builder) int {
	sb.WriteString("--- Registry Run Keys ---\n")
	count := 0

	runKeys := []struct {
		hive     registry.Key
		hiveName string
		path     string
	}{
		{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Run`},
		{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows\CurrentVersion\Run`},
		{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunServices`},
		{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`},
	}

	for _, rk := range runKeys {
		key, err := registry.OpenKey(rk.hive, rk.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		names, err := key.ReadValueNames(0)
		key.Close()
		if err != nil || len(names) == 0 {
			continue
		}

		key, err = registry.OpenKey(rk.hive, rk.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		for _, name := range names {
			val, _, err := key.GetStringValue(name)
			if err != nil {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [%s\\%s] %s = %s\n", rk.hiveName, rk.path, name, val))
			count++
		}
		key.Close()
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumStartupFolders checks Startup folders for HKCU and All Users.
func persistEnumStartupFolders(sb *strings.Builder) int {
	sb.WriteString("--- Startup Folders ---\n")
	count := 0

	folders := []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		filepath.Join(os.Getenv("PROGRAMDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
	}

	for _, folder := range folders {
		entries, err := os.ReadDir(folder)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.Name() == "desktop.ini" {
				continue
			}
			sb.WriteString(fmt.Sprintf("  %s\\%s\n", folder, entry.Name()))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumWinlogon checks Winlogon Shell, Userinit, and Notify keys.
func persistEnumWinlogon(sb *strings.Builder) int {
	sb.WriteString("--- Winlogon ---\n")
	count := 0

	winlogonPath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, winlogonPath, registry.QUERY_VALUE)
	if err != nil {
		sb.WriteString("  (cannot open Winlogon key)\n\n")
		return 0
	}
	defer key.Close()

	checkValues := []struct {
		name     string
		expected string
	}{
		{"Shell", "explorer.exe"},
		{"Userinit", `C:\Windows\system32\userinit.exe,`},
		{"AppInit_DLLs", ""},
		{"TaskMan", ""},
	}

	for _, cv := range checkValues {
		val, _, err := key.GetStringValue(cv.name)
		if err != nil {
			continue
		}
		val = strings.TrimSpace(val)
		if val == "" || strings.EqualFold(val, cv.expected) {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s = %s", cv.name, val))
		if cv.expected != "" {
			sb.WriteString(fmt.Sprintf(" (default: %s)", cv.expected))
		}
		sb.WriteString("\n")
		count++
	}

	if count == 0 {
		sb.WriteString("  (all defaults)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumIFEO checks Image File Execution Options for debugger persistence.
func persistEnumIFEO(sb *strings.Builder) int {
	sb.WriteString("--- Image File Execution Options (Debugger) ---\n")
	count := 0

	ifeoPath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, ifeoPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		sb.WriteString("  (cannot open IFEO key)\n\n")
		return 0
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(0)
	if err != nil {
		sb.WriteString("  (cannot enumerate IFEO subkeys)\n\n")
		return 0
	}

	for _, sk := range subkeys {
		subkey, err := registry.OpenKey(registry.LOCAL_MACHINE, ifeoPath+`\`+sk, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		debugger, _, err := subkey.GetStringValue("Debugger")
		subkey.Close()
		if err != nil || debugger == "" {
			continue
		}
		sb.WriteString(fmt.Sprintf("  %s → Debugger: %s\n", sk, debugger))
		count++
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumAppInit checks AppInit_DLLs registry values.
func persistEnumAppInit(sb *strings.Builder) int {
	sb.WriteString("--- AppInit_DLLs ---\n")
	count := 0

	appInitPaths := []struct {
		path string
		desc string
	}{
		{`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, "64-bit"},
		{`SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`, "32-bit (WOW64)"},
	}

	for _, ap := range appInitPaths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, ap.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		loadAppInit, _, _ := key.GetIntegerValue("LoadAppInit_DLLs")
		appInitDLLs, _, err := key.GetStringValue("AppInit_DLLs")
		key.Close()

		if err != nil || appInitDLLs == "" {
			continue
		}
		enabled := "disabled"
		if loadAppInit != 0 {
			enabled = "ENABLED"
		}
		sb.WriteString(fmt.Sprintf("  [%s] AppInit_DLLs = %s (%s)\n", ap.desc, appInitDLLs, enabled))
		count++
	}

	if count == 0 {
		sb.WriteString("  (none configured)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumScheduledTasks enumerates non-Microsoft scheduled tasks via schtasks.exe.
func persistEnumScheduledTasks(sb *strings.Builder) int {
	sb.WriteString("--- Scheduled Tasks ---\n")
	count := 0

	out, err := execCmdTimeoutOutput("schtasks.exe", "/query", "/fo", "CSV", "/nh", "/v")
	if err != nil {
		sb.WriteString(fmt.Sprintf("  (schtasks query failed: %v)\n", err))
		sb.WriteString("\n")
		return 0
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := parseCSVLine(line)
		if len(fields) < 9 {
			continue
		}
		taskName := fields[1]
		taskToRun := fields[8]

		nameLower := strings.ToLower(taskName)
		if strings.HasPrefix(nameLower, `\microsoft\`) {
			continue
		}

		sb.WriteString(fmt.Sprintf("  %s → %s\n", taskName, taskToRun))
		count++
	}

	if count == 0 {
		sb.WriteString("  (no non-Microsoft tasks found)\n")
	}
	sb.WriteString("\n")
	return count
}

// parseCSVLine splits a CSV line respecting quoted fields.
func parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' {
			inQuotes = !inQuotes
		} else if c == ',' && !inQuotes {
			fields = append(fields, current.String())
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}
	fields = append(fields, current.String())
	return fields
}

// persistEnumServices checks for non-Microsoft services.
func persistEnumServices(sb *strings.Builder) int {
	sb.WriteString("--- Non-Microsoft Services ---\n")
	count := 0

	servicesPath := `SYSTEM\CurrentControlSet\Services`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, servicesPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		sb.WriteString("  (cannot open Services key)\n\n")
		return 0
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(0)
	if err != nil {
		sb.WriteString("  (cannot enumerate Services)\n\n")
		return 0
	}

	for _, sk := range subkeys {
		svcKey, err := registry.OpenKey(registry.LOCAL_MACHINE, servicesPath+`\`+sk, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		svcType, _, err := svcKey.GetIntegerValue("Type")
		if err != nil {
			svcKey.Close()
			continue
		}

		if svcType != 16 && svcType != 32 && svcType != 0x110 && svcType != 0x120 {
			svcKey.Close()
			continue
		}

		imagePath, _, err := svcKey.GetStringValue("ImagePath")
		svcKey.Close()
		if err != nil || imagePath == "" {
			continue
		}

		imgLower := strings.ToLower(imagePath)
		if strings.Contains(imgLower, `\windows\`) ||
			strings.Contains(imgLower, `%systemroot%`) ||
			strings.Contains(imgLower, `%windir%`) ||
			strings.Contains(imgLower, `\microsoft.net\`) ||
			strings.Contains(imgLower, `\windows defender\`) ||
			strings.Contains(imgLower, `%programfiles%\windows`) {
			continue
		}

		sb.WriteString(fmt.Sprintf("  %s → %s\n", sk, imagePath))
		count++
	}

	if count == 0 {
		sb.WriteString("  (only standard Microsoft services)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumPortMonitors checks for non-standard port monitors (T1547.010).
func persistEnumPortMonitors(sb *strings.Builder) int {
	sb.WriteString("--- Port Monitors (HKLM\\...\\Print\\Monitors) ---\n")
	count := 0

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, portMonitorRegBase, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		sb.WriteString("  (cannot open Print\\Monitors key)\n\n")
		return 0
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(0)
	if err != nil {
		sb.WriteString("  (cannot enumerate port monitors)\n\n")
		return 0
	}

	legitimate := map[string]bool{
		"Local Port":                   true,
		"Standard TCP/IP Port":         true,
		"USB Monitor":                  true,
		"WSD Port":                     true,
		"Microsoft Shared Fax Monitor": true,
		"TCPMON.DLL":                   true,
	}

	for _, name := range subkeys {
		if legitimate[name] {
			continue
		}
		subPath := portMonitorRegBase + `\` + name
		subKey, err := registry.OpenKey(registry.LOCAL_MACHINE, subPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		driver, _, err := subKey.GetStringValue("Driver")
		subKey.Close()
		if err == nil && driver != "" {
			sb.WriteString(fmt.Sprintf("  ⚠ %s → %s\n", name, driver))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (no non-standard port monitors)\n")
	}
	sb.WriteString("\n")
	return count
}
