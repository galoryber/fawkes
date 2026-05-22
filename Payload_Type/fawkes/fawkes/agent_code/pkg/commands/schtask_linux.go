//go:build linux

package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
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

type schtaskArgs struct {
	Action  string `json:"action"`
	Name    string `json:"name"`
	Program string `json:"program"`
	Args    string `json:"args"`
	Trigger string `json:"trigger"`
	Time    string `json:"time"`
	User    string `json:"user"`
	RunNow  bool   `json:"run_now"`
	Filter  string `json:"filter"`
}

type schtaskListEntry struct {
	Name        string `json:"name"`
	State       string `json:"state"`
	Type        string `json:"type"`
	NextRunTime string `json:"next_run_time,omitempty"`
}

func (c *SchtaskCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := requireParams[schtaskArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return schtaskLinuxList(args.Filter)
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

func schtaskLinuxList(filter string) structs.CommandResult {
	var entries []schtaskListEntry
	filterLower := strings.ToLower(filter)

	entries = append(entries, enumerateUserCrontab()...)
	entries = append(entries, enumerateSystemCrontab()...)
	entries = append(entries, enumerateCronDirs()...)
	entries = append(entries, enumerateSystemdTimers()...)
	entries = append(entries, enumerateAtJobs()...)

	if filterLower != "" {
		var filtered []schtaskListEntry
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.Name), filterLower) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	if len(entries) == 0 {
		return successResult("[]")
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}
	return successResult(string(data))
}

func enumerateUserCrontab() []schtaskListEntry {
	out, err := execCmdTimeout("crontab", "-l")
	if err != nil {
		return nil
	}
	currentUser := "unknown"
	if u, err := user.Current(); err == nil {
		currentUser = u.Username
	}
	return parseCrontabLines(string(out), fmt.Sprintf("crontab(%s)", currentUser))
}

func enumerateSystemCrontab() []schtaskListEntry {
	data, err := os.ReadFile("/etc/crontab")
	if err != nil {
		return nil
	}
	return parseCrontabLines(string(data), "system(/etc/crontab)")
}

func enumerateCronDirs() []schtaskListEntry {
	var entries []schtaskListEntry
	cronDirs := []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}

	for _, dir := range cronDirs {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		dirBase := filepath.Base(dir)
		for _, f := range files {
			if f.IsDir() || strings.HasPrefix(f.Name(), ".") {
				continue
			}
			fullPath := filepath.Join(dir, f.Name())
			if dirBase == "cron.d" {
				data, err := os.ReadFile(fullPath)
				if err != nil {
					continue
				}
				entries = append(entries, parseCrontabLines(string(data), fmt.Sprintf("cron.d(%s)", f.Name()))...)
			} else {
				entries = append(entries, schtaskListEntry{
					Name:  fullPath,
					State: "Active",
					Type:  dirBase,
				})
			}
		}
	}
	return entries
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
		// systemctl list-timers --no-legend format:
		// NEXT                         LEFT          LAST                         PASSED       UNIT                         ACTIVATES
		// Thu 2026-05-22 08:00:00 CDT  15min left    Thu 2026-05-22 07:30:00 CDT  14min ago    apt-daily.timer              apt-daily.service
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

func enumerateAtJobs() []schtaskListEntry {
	out, err := execCmdTimeout("atq")
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return nil
	}

	var entries []schtaskListEntry
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// atq format: "1\tThu May 22 09:00:00 2026 a user"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		jobID := fields[0]
		state := "queued"
		scheduledTime := ""
		if len(fields) >= 6 {
			scheduledTime = strings.Join(fields[1:6], " ")
		}
		if len(fields) >= 7 {
			queueLetter := fields[6]
			if queueLetter == "=" {
				state = "running"
			}
		}

		entries = append(entries, schtaskListEntry{
			Name:        fmt.Sprintf("at-job-%s", jobID),
			State:       state,
			Type:        "at",
			NextRunTime: scheduledTime,
		})
	}
	return entries
}

func parseCrontabLines(content, source string) []schtaskListEntry {
	var entries []schtaskListEntry
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "SHELL=") || strings.HasPrefix(line, "PATH=") ||
			strings.HasPrefix(line, "MAILTO=") || strings.HasPrefix(line, "HOME=") {
			continue
		}

		fields := strings.Fields(line)

		var schedule, command string
		if strings.HasPrefix(line, "@") {
			if len(fields) < 2 {
				continue
			}
			schedule = fields[0]
			if isSystemCrontab(source) && len(fields) >= 3 {
				command = strings.Join(fields[2:], " ")
			} else {
				command = strings.Join(fields[1:], " ")
			}
		} else {
			if len(fields) < 6 {
				continue
			}
			schedule = strings.Join(fields[:5], " ")
			if isSystemCrontab(source) && len(fields) >= 7 {
				command = strings.Join(fields[6:], " ")
			} else {
				command = strings.Join(fields[5:], " ")
			}
		}

		name := fmt.Sprintf("%s: %s %s", source, schedule, truncateStr(command, 80))
		entries = append(entries, schtaskListEntry{
			Name:  name,
			State: "Active",
			Type:  "crontab",
		})
	}
	return entries
}

func isSystemCrontab(source string) bool {
	return strings.Contains(source, "/etc/crontab") || strings.Contains(source, "cron.d(")
}

func schtaskLinuxQuery(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for query (systemd timer unit name or at job ID)")
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
			return errorf("Error querying timer '%s': %v", timerName, err)
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

func queryAtJob(name string) structs.CommandResult {
	jobID := strings.TrimPrefix(name, "at-job-")
	out, err := execCmdTimeout("at", "-c", jobID)
	if err != nil {
		return errorf("Error querying at job '%s': %v", jobID, err)
	}
	return successf("At Job %s:\n%s", jobID, string(out))
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
		return errorResult("Error: program is required for task creation")
	}

	trigger := strings.ToLower(args.Trigger)
	if trigger == "" || trigger == "onlogon" || trigger == "daily" || trigger == "once" ||
		trigger == "weekly" || trigger == "monthly" || trigger == "onidle" || trigger == "onstart" {
		return schtaskLinuxCreateCron(args)
	}
	if trigger == "systemd" || trigger == "timer" {
		return schtaskLinuxCreateSystemdTimer(args)
	}
	if trigger == "at" {
		return schtaskLinuxCreateAt(args)
	}

	return schtaskLinuxCreateCron(args)
}

func schtaskLinuxCreateCron(args schtaskArgs) structs.CommandResult {
	schedule := triggerToSchedule(args.Trigger, args.Time)

	command := args.Program
	if args.Args != "" {
		command += " " + args.Args
	}

	entry := fmt.Sprintf("%s %s", schedule, command)
	if args.Name != "" {
		entry += fmt.Sprintf(" # %s", args.Name)
	}

	cronArgs := []string{"-l"}
	if args.User != "" {
		cronArgs = append(cronArgs, "-u", args.User)
	}
	existing, _ := execCmdTimeout("crontab", cronArgs...)

	newCrontab := strings.TrimRight(string(existing), "\n")
	if newCrontab != "" {
		newCrontab += "\n"
	}
	newCrontab += entry + "\n"

	installArgs := []string{"-"}
	if args.User != "" {
		installArgs = []string{"-u", args.User, "-"}
	}
	cmd, cancel := execCmdCtx("crontab", installArgs...)
	defer cancel()
	cmd.Stdin = strings.NewReader(newCrontab)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("Error installing crontab: %v\n%s", err, string(out))
	}

	return successf("Created cron job:\n  Schedule: %s\n  Command:  %s", schedule, command)
}

func triggerToSchedule(trigger, timeStr string) string {
	hh, mm := "0", "0"
	if timeStr != "" {
		parts := strings.SplitN(timeStr, ":", 2)
		if len(parts) == 2 {
			hh = parts[0]
			mm = parts[1]
		}
	}

	switch strings.ToUpper(trigger) {
	case "DAILY":
		return fmt.Sprintf("%s %s * * *", mm, hh)
	case "WEEKLY":
		return fmt.Sprintf("%s %s * * 0", mm, hh)
	case "MONTHLY":
		return fmt.Sprintf("%s %s 1 * *", mm, hh)
	case "ONSTART":
		return "@reboot"
	case "ONIDLE":
		return "@reboot"
	case "ONCE":
		return fmt.Sprintf("%s %s * * *", mm, hh)
	default:
		return fmt.Sprintf("%s %s * * *", mm, hh)
	}
}

func schtaskLinuxCreateSystemdTimer(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for systemd timer creation")
	}

	unitName := args.Name
	if strings.HasSuffix(unitName, ".timer") {
		unitName = strings.TrimSuffix(unitName, ".timer")
	}

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
	timerContent += fmt.Sprintf("\n[Install]\nWantedBy=timers.target\n")

	servicePath := filepath.Join(unitDir, unitName+".service")
	timerPath := filepath.Join(unitDir, unitName+".timer")

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return errorf("Error writing service file: %v", err)
	}
	if err := os.WriteFile(timerPath, []byte(timerContent), 0644); err != nil {
		return errorf("Error writing timer file: %v", err)
	}

	scopeArgs := []string{}
	if !isRoot {
		scopeArgs = append(scopeArgs, "--user")
	}

	execCmdTimeout("systemctl", append(scopeArgs, "daemon-reload")...)
	out, err := execCmdTimeout("systemctl", append(scopeArgs, "enable", "--now", unitName+".timer")...)
	if err != nil {
		return errorf("Timer files created but enable failed: %v\n%s\nFiles: %s, %s", err, string(out), servicePath, timerPath)
	}

	return successf("Created systemd timer:\n  Service: %s\n  Timer:   %s\n  Command: %s\n  Schedule: %s", servicePath, timerPath, command, schedule)
}

func schtaskLinuxCreateAt(args schtaskArgs) structs.CommandResult {
	if args.Time == "" {
		return errorResult("Error: time is required for at job creation (HH:MM format)")
	}

	command := args.Program
	if args.Args != "" {
		command += " " + args.Args
	}

	cmd, cancel := execCmdCtx("at", args.Time)
	defer cancel()
	cmd.Stdin = strings.NewReader(command + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("Error creating at job: %v\n%s", err, string(out))
	}

	return successf("Created at job for %s:\n  Command: %s\n%s", args.Time, command, strings.TrimSpace(string(out)))
}

func schtaskLinuxDelete(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for deletion")
	}

	if strings.HasPrefix(args.Name, "at-job-") || isNumeric(args.Name) {
		jobID := strings.TrimPrefix(args.Name, "at-job-")
		out, err := execCmdTimeout("atrm", jobID)
		if err != nil {
			return errorf("Error deleting at job '%s': %v\n%s", jobID, err, string(out))
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

	execCmdTimeout("systemctl", append(scopeArgs, "stop", timerName)...)
	execCmdTimeout("systemctl", append(scopeArgs, "disable", timerName)...)

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

	execCmdTimeout("systemctl", append(scopeArgs, "daemon-reload")...)

	if removed == 0 {
		return errorf("No systemd unit files found for '%s'", unitName)
	}
	return successf("Deleted systemd timer '%s' (%d files removed)", timerName, removed)
}

func deleteCronEntry(args schtaskArgs) structs.CommandResult {
	cronArgs := []string{"-l"}
	if args.User != "" {
		cronArgs = append(cronArgs, "-u", args.User)
	}
	existing, err := execCmdTimeout("crontab", cronArgs...)
	if err != nil {
		return errorf("Error reading crontab: %v", err)
	}

	var kept []string
	removed := 0
	scanner := bufio.NewScanner(strings.NewReader(string(existing)))
	for scanner.Scan() {
		line := scanner.Text()
		if matchesCronEntry(line, args.Name) {
			removed++
			continue
		}
		kept = append(kept, line)
	}

	if removed == 0 {
		return errorf("No cron entry matching '%s' found", args.Name)
	}

	newCrontab := strings.Join(kept, "\n") + "\n"
	installArgs := []string{"-"}
	if args.User != "" {
		installArgs = []string{"-u", args.User, "-"}
	}
	cmd, cancel := execCmdCtx("crontab", installArgs...)
	defer cancel()
	cmd.Stdin = strings.NewReader(newCrontab)
	out, cmdErr := cmd.CombinedOutput()
	if cmdErr != nil {
		return errorf("Error updating crontab: %v\n%s", cmdErr, string(out))
	}

	return successf("Deleted %d cron entry/entries matching '%s'", removed, args.Name)
}

func matchesCronEntry(line, name string) bool {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return false
	}
	if strings.Contains(line, "# "+name) {
		return true
	}
	if strings.Contains(line, name) {
		return true
	}
	return false
}

func schtaskLinuxRun(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required to run a task (systemd timer/service unit name)")
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
		return errorf("Error starting '%s': %v\n%s", unitName, err, string(out))
	}

	return successf("Triggered execution of '%s'", unitName)
}

func schtaskLinuxSetEnabled(args schtaskArgs, enabled bool) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required (systemd timer unit name)")
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
		return errorf("Error %s timer '%s': %v\n%s", action, timerName, err, string(out))
	}

	label := "Enabled"
	if !enabled {
		label = "Disabled"
	}
	return successf("%s systemd timer '%s'", label, timerName)
}

func schtaskLinuxStop(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required to stop a task (systemd service/timer unit name)")
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
		return errorf("Error stopping '%s': %v\n%s", unitName, err, string(out))
	}

	return successf("Stopped '%s'", unitName)
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
