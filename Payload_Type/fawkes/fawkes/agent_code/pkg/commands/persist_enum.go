//go:build windows

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// PersistEnumCommand enumerates common Windows persistence mechanisms.
type PersistEnumCommand struct{}

func (c *PersistEnumCommand) Name() string { return "persist-enum" }
func (c *PersistEnumCommand) Description() string {
	return "Enumerate Windows persistence mechanisms — registry, startup, scheduled tasks, services, WMI (T1547)"
}

type persistEnumArgs struct {
	Category string `json:"category"` // all, registry, startup, tasks, services, wmi, ifeo, winlogon
}

func (c *PersistEnumCommand) Execute(task structs.Task) structs.CommandResult {
	var args persistEnumArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Error parsing parameters: %v", err)
		}
	}
	if args.Category == "" {
		args.Category = "all"
	}

	var sb strings.Builder
	sb.WriteString("=== Persistence Enumeration ===\n\n")

	cat := strings.ToLower(args.Category)
	found := 0

	if cat == "all" || cat == "registry" {
		found += persistEnumRegistry(&sb)
	}
	if cat == "all" || cat == "startup" {
		found += persistEnumStartupFolders(&sb)
	}
	if cat == "all" || cat == "winlogon" {
		found += persistEnumWinlogon(&sb)
	}
	if cat == "all" || cat == "ifeo" {
		found += persistEnumIFEO(&sb)
	}
	if cat == "all" || cat == "appinit" {
		found += persistEnumAppInit(&sb)
	}
	if cat == "all" || cat == "tasks" {
		found += persistEnumScheduledTasks(&sb)
	}
	if cat == "all" || cat == "services" {
		found += persistEnumServices(&sb)
	}

	sb.WriteString(fmt.Sprintf("\n=== Total: %d persistence items found ===\n", found))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

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
		expected string // expected default value
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
		// Non-default value found
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

// persistEnumScheduledTasks enumerates scheduled tasks via registry.
func persistEnumScheduledTasks(sb *strings.Builder) int {
	sb.WriteString("--- Scheduled Tasks (Registry) ---\n")
	count := 0

	// Check Task Scheduler registry (tasks with actions)
	taskPath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`
	count += persistEnumTaskTree(sb, taskPath, "")

	if count == 0 {
		sb.WriteString("  (none found in registry)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumTaskTree recursively walks the task scheduler tree.
func persistEnumTaskTree(sb *strings.Builder, basePath string, prefix string) int {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, basePath, registry.READ)
	if err != nil {
		return 0
	}
	defer key.Close()

	count := 0

	// Check if this node has a task ID (leaf node = actual scheduled task)
	id, _, err := key.GetStringValue("Id")
	if err == nil && id != "" {
		taskName := prefix
		if taskName == "" {
			taskName = "(root)"
		}
		// Look up the task URI in TaskCache\Tasks\{id}
		actionPath := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\` + id
		actionKey, err := registry.OpenKey(registry.LOCAL_MACHINE, actionPath, registry.QUERY_VALUE)
		if err == nil {
			uri, _, uriErr := actionKey.GetStringValue("URI")
			actionKey.Close()
			if uriErr == nil && uri != "" {
				// Skip common Microsoft/Windows built-in tasks
				uriLower := strings.ToLower(uri)
				if !strings.HasPrefix(uriLower, `\microsoft\`) {
					sb.WriteString(fmt.Sprintf("  %s\n", uri))
					count++
				}
			} else {
				sb.WriteString(fmt.Sprintf("  %s (ID: %s)\n", taskName, id))
				count++
			}
		}
	}

	// Enumerate sub-keys
	subkeys, err := key.ReadSubKeyNames(0)
	if err != nil {
		return count
	}

	for _, sk := range subkeys {
		childPath := basePath + `\` + sk
		childPrefix := prefix + `\` + sk
		count += persistEnumTaskTree(sb, childPath, childPrefix)
	}

	return count
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

		// Check service type (1=kernel driver, 2=file system driver, 16/32=win32 service)
		svcType, _, err := svcKey.GetIntegerValue("Type")
		if err != nil {
			svcKey.Close()
			continue
		}

		// Only enumerate Win32 services (type 16 or 32) and auto-start/manual-start
		if svcType != 16 && svcType != 32 && svcType != 0x110 && svcType != 0x120 {
			svcKey.Close()
			continue
		}

		imagePath, _, err := svcKey.GetStringValue("ImagePath")
		svcKey.Close()
		if err != nil || imagePath == "" {
			continue
		}

		// Skip services under standard Windows/Microsoft directories.
		// We only want to surface third-party or unusual services.
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
