package commands

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// PsCommand implements the ps command
type PsCommand struct{}

// Name returns the command name
func (c *PsCommand) Name() string {
	return "ps"
}

// Description returns the command description
func (c *PsCommand) Description() string {
	return "List processes - displays running processes with details"
}

// ProcessInfo represents process information
type ProcessInfo struct {
	PID         string `json:"pid"`
	PPID        string `json:"ppid,omitempty"`
	Name        string `json:"name"`
	Arch        string `json:"arch,omitempty"`
	User        string `json:"user,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
}

// Execute executes the ps command
func (c *PsCommand) Execute(task structs.Task) structs.CommandResult {
	var output string
	var err error

	if runtime.GOOS == "windows" {
		output, err = getWindowsProcesses()
	} else {
		output, err = getUnixProcesses()
	}

	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing processes: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

func getWindowsProcesses() (string, error) {
	// Use WMIC to get detailed process information
	// Format: Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine
	cmd := exec.Command("wmic", "process", "get",
		"Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine", "/format:csv")

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback to simpler tasklist if wmic fails
		cmd = exec.Command("tasklist", "/v", "/fo", "csv")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return "", err
		}
	}

	return formatProcessOutput(string(output), "windows")
}

func getUnixProcesses() (string, error) {
	// Use ps with detailed output
	// -e: all processes, -o: custom format
	cmd := exec.Command("ps", "-eo", "pid,ppid,user,comm,args")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	return formatProcessOutput(string(output), "unix")
}

func formatProcessOutput(output string, osType string) (string, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) == 0 {
		return "No processes found", nil
	}

	var result strings.Builder

	if osType == "windows" {
		// Parse CSV output from WMIC or tasklist
		result.WriteString(fmt.Sprintf("%-8s %-8s %-30s %-60s\n", "PID", "PPID", "Name", "Command Line"))
		result.WriteString(strings.Repeat("-", 120) + "\n")

		for i, line := range lines {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue // Skip header or empty lines
			}
			// Basic parsing - in production you'd want more robust CSV parsing
			result.WriteString(line + "\n")
		}
	} else {
		// Unix output is already well-formatted
		result.WriteString(output)
	}

	return result.String(), nil
}
