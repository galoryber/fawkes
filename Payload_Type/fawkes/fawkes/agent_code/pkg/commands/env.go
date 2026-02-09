package commands

import (
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
	return "List environment variables, optionally filtered by name"
}

// Execute executes the env command
func (c *EnvCommand) Execute(task structs.Task) structs.CommandResult {
	filter := strings.TrimSpace(task.Params)

	envVars := os.Environ()
	sort.Strings(envVars)

	if filter == "" {
		return structs.CommandResult{
			Output:    strings.Join(envVars, "\n"),
			Status:    "success",
			Completed: true,
		}
	}

	// Filter: show variables whose name contains the filter (case-insensitive)
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
