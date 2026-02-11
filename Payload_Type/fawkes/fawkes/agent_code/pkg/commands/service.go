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

type ServiceCommand struct{}

func (c *ServiceCommand) Name() string {
	return "service"
}

func (c *ServiceCommand) Description() string {
	return "Manage Windows services (query, start, stop, create, delete, list)"
}

type serviceArgs struct {
	Action  string `json:"action"`
	Name    string `json:"name"`
	BinPath string `json:"binpath"`
	Display string `json:"display"`
	Start   string `json:"start"`
}

func (c *ServiceCommand) Execute(task structs.Task) structs.CommandResult {
	var args serviceArgs

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
	case "query":
		return serviceQuery(args)
	case "start":
		return serviceStart(args)
	case "stop":
		return serviceStop(args)
	case "create":
		return serviceCreate(args)
	case "delete":
		return serviceDelete(args)
	case "list":
		return serviceList()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: query, start, stop, create, delete, list", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func serviceQuery(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for service query",
			Status:    "error",
			Completed: true,
		}
	}

	output, err := runSC([]string{"query", args.Name})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying service '%s': %v\n%s", args.Name, err, output),
			Status:    "error",
			Completed: true,
		}
	}

	// Also get the service config for more detail
	configOutput, configErr := runSC([]string{"qc", args.Name})
	if configErr == nil {
		output += "\n\nConfiguration:\n" + configOutput
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Service '%s':\n%s", args.Name, output),
		Status:    "success",
		Completed: true,
	}
}

func serviceStart(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required to start a service",
			Status:    "error",
			Completed: true,
		}
	}

	output, err := runSC([]string{"start", args.Name})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error starting service '%s': %v\n%s", args.Name, err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Started service '%s':\n%s", args.Name, output),
		Status:    "success",
		Completed: true,
	}
}

func serviceStop(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required to stop a service",
			Status:    "error",
			Completed: true,
		}
	}

	output, err := runSC([]string{"stop", args.Name})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error stopping service '%s': %v\n%s", args.Name, err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Stopped service '%s':\n%s", args.Name, output),
		Status:    "success",
		Completed: true,
	}
}

func serviceCreate(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for service creation",
			Status:    "error",
			Completed: true,
		}
	}
	if args.BinPath == "" {
		return structs.CommandResult{
			Output:    "Error: binpath is required for service creation",
			Status:    "error",
			Completed: true,
		}
	}

	cmdArgs := []string{"create", args.Name, fmt.Sprintf("binpath= %s", args.BinPath)}

	if args.Display != "" {
		cmdArgs = append(cmdArgs, fmt.Sprintf("displayname= %s", args.Display))
	}

	startType := args.Start
	if startType == "" {
		startType = "demand"
	}
	cmdArgs = append(cmdArgs, fmt.Sprintf("start= %s", startType))

	output, err := runSC(cmdArgs)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating service '%s': %v\n%s", args.Name, err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Created service '%s':\n  BinPath: %s\n  Start:   %s\n\n%s", args.Name, args.BinPath, startType, output),
		Status:    "success",
		Completed: true,
	}
}

func serviceDelete(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for service deletion",
			Status:    "error",
			Completed: true,
		}
	}

	output, err := runSC([]string{"delete", args.Name})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error deleting service '%s': %v\n%s", args.Name, err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Deleted service '%s':\n%s", args.Name, output),
		Status:    "success",
		Completed: true,
	}
}

func serviceList() structs.CommandResult {
	output, err := runSC([]string{"query", "type=", "service", "state=", "all"})
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing services: %v\n%s", err, output),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Windows Services:\n%s", output),
		Status:    "success",
		Completed: true,
	}
}

func runSC(args []string) (string, error) {
	cmd := exec.Command("sc.exe", args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
