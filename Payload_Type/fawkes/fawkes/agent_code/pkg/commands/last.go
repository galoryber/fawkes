package commands

import (
	"encoding/json"
	"fmt"

	"fawkes/pkg/structs"
)

type LastCommand struct{}

func (c *LastCommand) Name() string { return "last" }
func (c *LastCommand) Description() string {
	return "Show recent login history and session information"
}

type lastArgs struct {
	Count int    `json:"count"` // Number of entries to show (default: 25)
	User  string `json:"user"`  // Filter by username
}

// lastLoginEntry is the JSON output format for browser script rendering
type lastLoginEntry struct {
	User      string `json:"user"`
	TTY       string `json:"tty"`
	From      string `json:"from"`
	LoginTime string `json:"login_time"`
	Duration  string `json:"duration,omitempty"`
}

func (c *LastCommand) Execute(task structs.Task) structs.CommandResult {
	args := lastArgs{Count: 25}
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &args)
	}
	if args.Count <= 0 {
		args.Count = 25
	}

	entries := lastPlatform(args)
	if len(entries) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	jsonBytes, err := json.Marshal(entries)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(jsonBytes),
		Status:    "success",
		Completed: true,
	}
}
