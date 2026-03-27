package commands

import (
	"encoding/json"
	"strings"

	"fawkes/pkg/structs"
)

type LastCommand struct{}

func (c *LastCommand) Name() string { return "last" }
func (c *LastCommand) Description() string {
	return "Show login history, failed login attempts, and system reboot events"
}

type lastArgs struct {
	Action string `json:"action"` // logins (default), failed, reboot
	Count  int    `json:"count"`  // Number of entries to show (default: 25)
	User   string `json:"user"`   // Filter by username
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

	action := strings.ToLower(args.Action)
	if action == "" {
		action = "logins"
	}

	var entries []lastLoginEntry

	switch action {
	case "logins":
		entries = lastPlatform(args)
	case "failed":
		entries = lastFailedPlatform(args)
	case "reboot":
		entries = lastRebootPlatform(args)
	default:
		return errorf("Unknown action: %s. Use: logins, failed, reboot", args.Action)
	}

	if len(entries) == 0 {
		return successResult("[]")
	}

	jsonBytes, err := json.Marshal(entries)
	if err != nil {
		return errorf("Error: %v", err)
	}

	return successResult(string(jsonBytes))
}
