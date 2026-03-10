package commands

import (
	"encoding/json"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// SetenvCommand implements the setenv command
type SetenvCommand struct{}

// Name returns the command name
func (c *SetenvCommand) Name() string {
	return "setenv"
}

// Description returns the command description
func (c *SetenvCommand) Description() string {
	return "Set or unset environment variables"
}

type setenvArgs struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

// Execute executes the setenv command
func (c *SetenvCommand) Execute(task structs.Task) structs.CommandResult {
	var args setenvArgs

	// Try JSON first, fall back to manual parsing
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Manual parsing: "set NAME=VALUE" or "unset NAME"
		params := strings.TrimSpace(task.Params)
		if strings.HasPrefix(params, "unset ") {
			args.Action = "unset"
			args.Name = strings.TrimSpace(strings.TrimPrefix(params, "unset "))
		} else if strings.HasPrefix(params, "set ") {
			args.Action = "set"
			rest := strings.TrimPrefix(params, "set ")
			if idx := strings.Index(rest, "="); idx >= 0 {
				args.Name = rest[:idx]
				args.Value = rest[idx+1:]
			} else {
				return errorResult("Error: set requires NAME=VALUE format")
			}
		} else {
			return errorResult("Error: could not parse arguments. Use JSON or 'set NAME=VALUE' / 'unset NAME'")
		}
	}

	args.Name = strings.TrimSpace(args.Name)
	if args.Name == "" {
		return errorResult("Error: variable name is required")
	}

	switch args.Action {
	case "set":
		if err := os.Setenv(args.Name, args.Value); err != nil {
			return errorf("Error setting %s: %v", args.Name, err)
		}
		return successf("Set %s=%s", args.Name, args.Value)

	case "unset":
		if err := os.Unsetenv(args.Name); err != nil {
			return errorf("Error unsetting %s: %v", args.Name, err)
		}
		return successf("Unset %s", args.Name)

	default:
		return errorf("Error: unknown action %q (use 'set' or 'unset')", args.Action)
	}
}
