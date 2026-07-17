//go:build linux

package commands

import (
	"bufio"
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
	return "Manage Linux scheduled tasks: crontab, systemd timers, and at jobs (list, query, create, delete, run, enable, disable, stop)"
}

func (c *SchtaskCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := requireParams[schtaskArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return schtaskUnixListCommon(args.Filter, enumerateSystemdTimers())
	case "query":
		return schtaskLinuxQuery(args)
	case "create":
		return schtaskLinuxCreate(args)
	case "delete":
		return schtaskLinuxDelete(args)
	case "run":
		return schtaskLinuxRun(args)
	case "enable":
		return schtaskLinuxSetEnabled(args, true)
	case "disable":
		return schtaskLinuxSetEnabled(args, false)
	case "stop":
		return schtaskLinuxStop(args)
	default:
		return errorf("Unknown action: %s. Use: list, query, create, delete, run, enable, disable, stop", args.Action)
	}
}

func enumerateSystemdTimers() []schtaskListEntry {
	out, err := execCmdTimeout("systemctl", "list-timers", "--all", "--no-pager", "--no-legend")
	if err != nil {
		userOut, userErr := execCmdTimeout("systemctl", "--user", "list-timers", "--all", "--no-pager", "--no-legend")
		if userErr != nil {
			return nil
		}
		out = userOut
	}

	var entries []schtaskListEntry
	entries = append(entries, parseSystemctlTimerOutput(string(out), "system")...)

	userOut, userErr := execCmdTimeout("systemctl", "--user", "list-timers", "--all", "--no-pager", "--no-legend")
	if userErr == nil && len(userOut) > 0 {
		entries = append(entries, parseSystemctlTimerOutput(string(userOut), "user")...)
	}

	return entries
}

func parseSystemctlTimerOutput(output, scope string) []schtaskListEntry {
	var entries []schtaskListEntry
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		var unitName, nextRun, activates string
		for i, f := range fields {
			if strings.HasSuffix(f, ".timer") {
				unitName = f
				if i+1 < len(fields) {
					activates = fields[i+1]
				}
				break
			}
		}
		if unitName == "" {
			continue
		}

		if len(fields) >= 3 && !strings.HasSuffix(fields[0], ".timer") {
			nextRun = strings.Join(fields[:3], " ")
			if nextRun == "n/a n/a n/a" {
				nextRun = "n/a"
			}
		}

		state := "waiting"
		if strings.Contains(line, "n/a") && strings.Count(line, "n/a") >= 2 {
			state = "inactive"
		}

		name := fmt.Sprintf("%s [%s]", unitName, scope)
		if activates != "" {
			name = fmt.Sprintf("%s → %s [%s]", unitName, activates, scope)
		}

		entries = append(entries, schtaskListEntry{
			Name:        name,
			State:       state,
			Type:        "systemd-timer",
			NextRunTime: nextRun,
		})
	}
	return entries
}

func schtaskLinuxQuery(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required for query (systemd timer unit name or at job ID)")
	}

	if strings.HasPrefix(args.Name, "at-job-") || isNumeric(args.Name) {
		return queryAtJob(args.Name)
	}

	timerName := args.Name
	if !strings.HasSuffix(timerName, ".timer") {
		timerName += ".timer"
	}
	return querySystemdTimer(timerName)
}

func querySystemdTimer(timerName string) structs.CommandResult {
	out, err := execCmdTimeout("systemctl", "show", timerName, "--no-pager")
	if err != nil {
		userOut, userErr := execCmdTimeout("systemctl", "--user", "show", timerName, "--no-pager")
		if userErr != nil {
			return errorf("querying timer '%s': %v", timerName, err)
		}
		out = userOut
	}

	props := parseSystemctlShow(string(out))
	if props["LoadState"] == "not-found" {
		return errorf("Timer '%s' not found", timerName)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Timer: %s\n", timerName))
	for _, key := range []string{"Description", "LoadState", "ActiveState", "SubState",
		"TimersCalendar", "TimersMonotonic", "NextElapseUSecRealtime",
		"LastTriggerUSec", "Unit", "Triggers"} {
		if v, ok := props[key]; ok && v != "" && v != "0" {
			sb.WriteString(fmt.Sprintf("%s: %s\n", key, v))
		}
	}

	return successResult(sb.String())
}

func parseSystemctlShow(output string) map[string]string {
	props := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		props[line[:idx]] = line[idx+1:]
	}
	return props
}

func schtaskLinuxCreate(args schtaskArgs) structs.CommandResult {
	if args.Program == "" {
		return errorResult("program is required for task creation")
	}

	trigger := strings.ToLower(args.Trigger)
	if trigger == "systemd" || trigger == "timer" {
		return schtaskLinuxCreateSystemdTimer(args)
	}
	if trigger == "at" {
		return schtaskCreateAt(args)
	}
	return schtaskCreateCron(args)
}

func schtaskLinuxCreateSystemdTimer(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required for systemd timer creation")
	}

	unitName := args.Name
	unitName = strings.TrimSuffix(unitName, ".timer")

	command := args.Program
	if args.Args != "" {
		command += " " + args.Args
	}

	isRoot := os.Getuid() == 0
	var unitDir string
	if isRoot {
		unitDir = "/etc/systemd/system"
	} else {
		home, _ := os.UserHomeDir()
		unitDir = filepath.Join(home, ".config", "systemd", "user")
		os.MkdirAll(unitDir, 0755)
	}

	schedule := "daily"
	if args.Time != "" {
		schedule = "*-*-* " + args.Time + ":00"
	}
	switch strings.ToUpper(args.Trigger) {
	case "DAILY":
		schedule = "daily"
	case "WEEKLY":
		schedule = "weekly"
	case "MONTHLY":
		schedule = "monthly"
	case "ONSTART":
		schedule = ""
	}

	serviceContent := fmt.Sprintf("[Unit]\nDescription=%s\n\n[Service]\nType=oneshot\nExecStart=%s\n", unitName, command)
	timerContent := fmt.Sprintf("[Unit]\nDescription=%s timer\n\n[Timer]\n", unitName)
	if schedule != "" {
		timerContent += fmt.Sprintf("OnCalendar=%s\nPersistent=true\n", schedule)
	} else {
		timerContent += "OnBootSec=60\n"
	}
	timerContent += "\n[Install]\nWantedBy=timers.target\n"

	servicePath := filepath.Join(unitDir, unitName+".service")
	timerPath := filepath.Join(unitDir, unitName+".timer")

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return errorf("writing service file: %v", err)
	}
	if err := os.WriteFile(timerPath, []byte(timerContent), 0644); err != nil {
		return errorf("writing timer file: %v", err)
	}

	scopeArgs := []string{}
	if !isRoot {
		scopeArgs = append(scopeArgs, "--user")
	}

	_, _ = execCmdTimeout("systemctl", append(scopeArgs, "daemon-reload")...)
	out, err := execCmdTimeout("systemctl", append(scopeArgs, "enable", "--now", unitName+".timer")...)
	if err != nil {
		return errorf("Timer files created but enable failed: %v\n%s\nFiles: %s, %s", err, string(out), servicePath, timerPath)
	}

	return successf("Created systemd timer:\n  Service: %s\n  Timer:   %s\n  Command: %s\n  Schedule: %s", servicePath, timerPath, command, schedule)
}

func schtaskLinuxDelete(args schtaskArgs) structs.CommandResult {
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

	if strings.HasSuffix(args.Name, ".timer") || strings.Contains(args.Name, ".") {
		return deleteSystemdTimer(args.Name)
	}

	return deleteCronEntry(args)
}

func deleteSystemdTimer(name string) structs.CommandResult {
	timerName := name
	if !strings.HasSuffix(timerName, ".timer") {
		timerName += ".timer"
	}
	unitName := strings.TrimSuffix(timerName, ".timer")

	isRoot := os.Getuid() == 0
	scopeArgs := []string{}
	if !isRoot {
		scopeArgs = append(scopeArgs, "--user")
	}

	_, _ = execCmdTimeout("systemctl", append(scopeArgs, "stop", timerName)...)
	_, _ = execCmdTimeout("systemctl", append(scopeArgs, "disable", timerName)...)

	var unitDir string
	if isRoot {
		unitDir = "/etc/systemd/system"
	} else {
		home, _ := os.UserHomeDir()
		unitDir = filepath.Join(home, ".config", "systemd", "user")
	}

	removed := 0
	for _, suffix := range []string{".timer", ".service"} {
		path := filepath.Join(unitDir, unitName+suffix)
		if err := os.Remove(path); err == nil {
			removed++
		}
	}

	_, _ = execCmdTimeout("systemctl", append(scopeArgs, "daemon-reload")...)

	if removed == 0 {
		return errorf("No systemd unit files found for '%s'", unitName)
	}
	return successf("Deleted systemd timer '%s' (%d files removed)", timerName, removed)
}

func schtaskLinuxRun(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required to run a task (systemd timer/service unit name)")
	}

	unitName := args.Name
	if strings.HasSuffix(unitName, ".timer") {
		unitName = strings.TrimSuffix(unitName, ".timer") + ".service"
	}
	if !strings.HasSuffix(unitName, ".service") {
		unitName += ".service"
	}

	isRoot := os.Getuid() == 0
	runArgs := []string{}
	if !isRoot {
		runArgs = append(runArgs, "--user")
	}
	runArgs = append(runArgs, "start", unitName)

	out, err := execCmdTimeout("systemctl", runArgs...)
	if err != nil {
		return errorf("starting '%s': %v\n%s", unitName, err, string(out))
	}

	return successf("Triggered execution of '%s'", unitName)
}

func schtaskLinuxSetEnabled(args schtaskArgs, enabled bool) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required (systemd timer unit name)")
	}

	timerName := args.Name
	if !strings.HasSuffix(timerName, ".timer") {
		timerName += ".timer"
	}

	isRoot := os.Getuid() == 0
	scopeArgs := []string{}
	if !isRoot {
		scopeArgs = append(scopeArgs, "--user")
	}

	action := "enable"
	if !enabled {
		action = "disable"
	}

	out, err := execCmdTimeout("systemctl", append(scopeArgs, action, timerName)...)
	if err != nil {
		return errorf("%s timer '%s': %v\n%s", action, timerName, err, string(out))
	}

	label := "Enabled"
	if !enabled {
		label = "Disabled"
	}
	return successf("%s systemd timer '%s'", label, timerName)
}

func schtaskLinuxStop(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("name is required to stop a task (systemd service/timer unit name)")
	}

	unitName := args.Name
	if !strings.HasSuffix(unitName, ".service") && !strings.HasSuffix(unitName, ".timer") {
		unitName += ".service"
	}

	isRoot := os.Getuid() == 0
	stopArgs := []string{}
	if !isRoot {
		stopArgs = append(stopArgs, "--user")
	}
	stopArgs = append(stopArgs, "stop", unitName)

	out, err := execCmdTimeout("systemctl", stopArgs...)
	if err != nil {
		return errorf("stopping '%s': %v\n%s", unitName, err, string(out))
	}

	return successf("Stopped '%s'", unitName)
}
