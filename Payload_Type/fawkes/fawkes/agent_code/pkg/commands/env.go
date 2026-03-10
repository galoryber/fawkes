package commands

import (
	"encoding/json"
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
		return errorf("Unknown action: %s. Use: list, get, set, unset", args.Action)
	}
}

func envList(filter string) structs.CommandResult {
	envVars := os.Environ()
	sort.Strings(envVars)

	if filter == "" {
		return successResult(strings.Join(envVars, "\n"))
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
		return successf("No environment variables matching '%s'", filter)
	}

	return successResult(strings.Join(matched, "\n"))
}

func envGet(name string) structs.CommandResult {
	if name == "" {
		return errorResult("Error: name is required for get action")
	}

	value, exists := os.LookupEnv(name)
	if !exists {
		return successf("Environment variable '%s' is not set", name)
	}

	return successf("%s=%s", name, value)
}

func envSet(name, value string) structs.CommandResult {
	if name == "" {
		return errorResult("Error: name is required for set action")
	}

	oldValue, existed := os.LookupEnv(name)
	if err := os.Setenv(name, value); err != nil {
		return errorf("Error setting %s: %v", name, err)
	}

	if existed {
		return successf("Updated %s (was: %s)", name, oldValue)
	}
	return successf("Set %s=%s", name, value)
}

func envUnset(name string) structs.CommandResult {
	if name == "" {
		return errorResult("Error: name is required for unset action")
	}

	_, existed := os.LookupEnv(name)
	if !existed {
		return successf("Environment variable '%s' was not set", name)
	}

	if err := os.Unsetenv(name); err != nil {
		return errorf("Error unsetting %s: %v", name, err)
	}

	return successf("Unset %s", name)
}
