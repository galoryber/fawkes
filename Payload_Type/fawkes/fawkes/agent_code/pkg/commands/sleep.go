package commands

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

// SleepCommand implements the sleep command with agent access
type SleepCommand struct{}

// Name returns the command name
func (c *SleepCommand) Name() string {
	return "sleep"
}

// Description returns the command description
func (c *SleepCommand) Description() string {
	return "Update the sleep interval and jitter of the agent"
}

// Execute executes the sleep command (fallback without agent access)
func (c *SleepCommand) Execute(task structs.Task) structs.CommandResult {
	return structs.CommandResult{
		Output:    "Sleep command requires agent access",
		Status:    "error",
		Completed: true,
	}
}

// ExecuteWithAgent executes the sleep command with agent access
func (c *SleepCommand) ExecuteWithAgent(task structs.Task, agent *structs.Agent) structs.CommandResult {
	// Parse parameters
	var args struct {
		Interval     int    `json:"interval"`
		Jitter       int    `json:"jitter"`
		WorkingStart string `json:"working_start"` // HH:MM format, empty = no change, "00:00" with end "00:00" = disable
		WorkingEnd   string `json:"working_end"`   // HH:MM format
		WorkingDays  string `json:"working_days"`  // "1,2,3,4,5" format, empty = no change, "0" = disable
	}

	// Try to parse as JSON first
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// If not JSON, try to parse as space-separated values
		parts := strings.Fields(task.Params)
		if len(parts) >= 1 {
			if interval, err := strconv.Atoi(parts[0]); err == nil {
				args.Interval = interval
			} else {
				return structs.CommandResult{
					Output:    fmt.Sprintf("Invalid interval value: %s", parts[0]),
					Status:    "error",
					Completed: true,
				}
			}
		}
		if len(parts) >= 2 {
			if jitter, err := strconv.Atoi(parts[1]); err == nil {
				args.Jitter = jitter
			} else {
				return structs.CommandResult{
					Output:    fmt.Sprintf("Invalid jitter value: %s", parts[1]),
					Status:    "error",
					Completed: true,
				}
			}
		}
		if len(parts) >= 3 {
			args.WorkingStart = parts[2]
		}
		if len(parts) >= 4 {
			args.WorkingEnd = parts[3]
		}
		if len(parts) >= 5 {
			args.WorkingDays = parts[4]
		}
	}

	// Validate values
	if args.Interval < 0 {
		return structs.CommandResult{
			Output:    "Sleep interval cannot be negative",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Jitter < 0 || args.Jitter > 100 {
		return structs.CommandResult{
			Output:    "Jitter must be between 0 and 100",
			Status:    "error",
			Completed: true,
		}
	}

	// Update sleep parameters in the actual agent
	oldInterval := agent.SleepInterval
	oldJitter := agent.Jitter

	agent.UpdateSleepParams(args.Interval, args.Jitter)

	// Build output message
	output := fmt.Sprintf("Updated sleep parameters: interval=%ds, jitter=%d%% (was: %ds, %d%%)",
		args.Interval, args.Jitter, oldInterval, oldJitter)

	// Handle working hours update
	if args.WorkingStart != "" || args.WorkingEnd != "" {
		startMinutes, err := structs.ParseWorkingHoursTime(args.WorkingStart)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Invalid working_start: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		endMinutes, err := structs.ParseWorkingHoursTime(args.WorkingEnd)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Invalid working_end: %v", err),
				Status:    "error",
				Completed: true,
			}
		}

		var days []int
		if args.WorkingDays != "" && args.WorkingDays != "0" {
			days, err = structs.ParseWorkingDays(args.WorkingDays)
			if err != nil {
				return structs.CommandResult{
					Output:    fmt.Sprintf("Invalid working_days: %v", err),
					Status:    "error",
					Completed: true,
				}
			}
		}

		oldStart := structs.FormatWorkingHoursTime(agent.WorkingHoursStart)
		oldEnd := structs.FormatWorkingHoursTime(agent.WorkingHoursEnd)

		agent.UpdateWorkingHours(startMinutes, endMinutes, days)

		if startMinutes == 0 && endMinutes == 0 {
			output += "\nWorking hours: DISABLED (was: " + oldStart + "-" + oldEnd + ")"
		} else {
			output += fmt.Sprintf("\nWorking hours: %s-%s",
				structs.FormatWorkingHoursTime(startMinutes),
				structs.FormatWorkingHoursTime(endMinutes))
			if len(days) > 0 {
				output += fmt.Sprintf(" days=%v", days)
			}
			output += " (was: " + oldStart + "-" + oldEnd + ")"
		}
	} else if args.WorkingDays != "" {
		// Update only working days
		if args.WorkingDays == "0" {
			agent.WorkingDays = nil
			output += "\nWorking days: DISABLED (all days active)"
		} else {
			days, err := structs.ParseWorkingDays(args.WorkingDays)
			if err != nil {
				return structs.CommandResult{
					Output:    fmt.Sprintf("Invalid working_days: %v", err),
					Status:    "error",
					Completed: true,
				}
			}
			agent.WorkingDays = days
			output += fmt.Sprintf("\nWorking days: %v", days)
		}
	}

	// Log the change
	log.Printf("[INFO] Sleep parameters updated: interval=%d, jitter=%d", args.Interval, args.Jitter)

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}
