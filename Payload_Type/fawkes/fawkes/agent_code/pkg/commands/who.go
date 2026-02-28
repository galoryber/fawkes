package commands

import (
	"encoding/json"
	"fmt"

	"fawkes/pkg/structs"
)

// WhoCommand shows currently logged-in users/sessions
type WhoCommand struct{}

func (c *WhoCommand) Name() string        { return "who" }
func (c *WhoCommand) Description() string { return "Show currently logged-in users and active sessions" }

type whoArgs struct {
	All bool `json:"all"` // Show all sessions including system accounts
}

// whoSessionEntry is the JSON output format for browser script rendering
type whoSessionEntry struct {
	User      string `json:"user"`
	TTY       string `json:"tty"`
	LoginTime string `json:"login_time"`
	From      string `json:"from"`
	Status    string `json:"status"`
}

func (c *WhoCommand) Execute(task structs.Task) structs.CommandResult {
	var args whoArgs
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &args)
	}

	entries := whoPlatform(args)
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
