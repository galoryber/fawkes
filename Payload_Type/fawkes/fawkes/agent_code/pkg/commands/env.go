package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"fawkes/pkg/structs"
)

// EnvCommand implements the env command
type EnvCommand struct{}

// Name returns the command name
func (c *EnvCommand) Name() string {
	return "env"
}

// Description returns the command description
func (c *EnvCommand) Description() string {
	return "List, get, set, or unset environment variables"
}

type envArgs struct {
	Action string `json:"action"` // list (default), get, set, unset
	Name   string `json:"name"`   // variable name (for get/set/unset)
	Value  string `json:"value"`  // variable value (for set)
	Filter string `json:"filter"` // filter string (for list)
}

// Execute executes the env command
func (c *EnvCommand) Execute(task structs.Task) structs.CommandResult {
	var args envArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			// Backward compat: treat raw string as filter for list action
			args.Action = "list"
			args.Filter = strings.TrimSpace(task.Params)
		}
	}

	if args.Action == "" {
		args.Action = "list"
	}

	switch args.Action {
	case "list":
		return envList(args.Filter)
	case "get":
		return envGet(args.Name)
	case "set":
		return envSet(args.Name, args.Value)
	case "unset":
		return envUnset(args.Name)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: list, get, set, unset", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func envList(filter string) structs.CommandResult {
	envVars := os.Environ()
	sort.Strings(envVars)

	if filter == "" {
		return structs.CommandResult{
			Output:    strings.Join(envVars, "\n"),
			Status:    "success",
			Completed: true,
		}
	}

	upperFilter := strings.ToUpper(filter)
	var matched []string
	for _, e := range envVars {
		name := e
		if idx := strings.Index(e, "="); idx >= 0 {
			name = e[:idx]
		}
		if strings.Contains(strings.ToUpper(name), upperFilter) {
			matched = append(matched, e)
		}
	}

	if len(matched) == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("No environment variables matching '%s'", filter),
			Status:    "success",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    strings.Join(matched, "\n"),
		Status:    "success",
		Completed: true,
	}
}

func envGet(name string) structs.CommandResult {
	if name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for get action",
			Status:    "error",
			Completed: true,
		}
	}

	value, exists := os.LookupEnv(name)
	if !exists {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Environment variable '%s' is not set", name),
			Status:    "success",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("%s=%s", name, value),
		Status:    "success",
		Completed: true,
	}
}

func envSet(name, value string) structs.CommandResult {
	if name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for set action",
			Status:    "error",
			Completed: true,
		}
	}

	oldValue, existed := os.LookupEnv(name)
	if err := os.Setenv(name, value); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error setting %s: %v", name, err),
			Status:    "error",
			Completed: true,
		}
	}

	if existed {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Updated %s (was: %s)", name, oldValue),
			Status:    "success",
			Completed: true,
		}
	}
	return structs.CommandResult{
		Output:    fmt.Sprintf("Set %s=%s", name, value),
		Status:    "success",
		Completed: true,
	}
}

func envUnset(name string) structs.CommandResult {
	if name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for unset action",
			Status:    "error",
			Completed: true,
		}
	}

	_, existed := os.LookupEnv(name)
	if !existed {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Environment variable '%s' was not set", name),
			Status:    "success",
			Completed: true,
		}
	}

	if err := os.Unsetenv(name); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error unsetting %s: %v", name, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Unset %s", name),
		Status:    "success",
		Completed: true,
	}
}
