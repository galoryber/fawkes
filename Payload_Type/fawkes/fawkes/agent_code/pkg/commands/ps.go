package commands

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"fawkes/pkg/structs"

	"github.com/shirou/gopsutil/v3/process"
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

// PsArgs represents the arguments for ps command
type PsArgs struct {
	Verbose bool   `json:"verbose"`
	Filter  string `json:"filter"`
	PID     int32  `json:"pid"`
}

// ProcessInfo represents process information
type ProcessInfo struct {
	PID     int32  `json:"pid"`
	PPID    int32  `json:"ppid"`
	Name    string `json:"name"`
	Arch    string `json:"arch"`
	User    string `json:"user"`
	CmdLine string `json:"cmdline,omitempty"`
}

// Execute executes the ps command
func (c *PsCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse arguments
	args := PsArgs{}

	if task.Params != "" {
		// Try to parse as JSON first
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			// Parse command line arguments
			parts := strings.Fields(task.Params)
			for i := 0; i < len(parts); i++ {
				switch parts[i] {
				case "-v":
					args.Verbose = true
				case "-i":
					if i+1 < len(parts) {
						if pid, err := strconv.ParseInt(parts[i+1], 10, 32); err == nil {
							args.PID = int32(pid)
						}
						i++
					}
				default:
					// Assume it's a filter string
					args.Filter = parts[i]
				}
			}
		}
	}

	processes, err := getProcessList(args.Filter, args.PID)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing processes: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	output := formatProcessList(processes, args.Verbose)

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

func getProcessList(filter string, pid int32) ([]ProcessInfo, error) {
	// Get all processes
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var processes []ProcessInfo
	filterLower := strings.ToLower(filter)

	for _, p := range procs {
		// Apply PID filter if specified
		if pid > 0 && p.Pid != pid {
			continue
		}

		name, err := p.Name()
		if err != nil {
			continue
		}

		// Apply name filter if specified
		if filter != "" && !strings.Contains(strings.ToLower(name), filterLower) {
			continue
		}

		ppid, _ := p.Ppid()
		username, _ := p.Username()
		cmdline, _ := p.Cmdline()

		// Determine architecture
		arch := runtime.GOARCH
		if runtime.GOOS == "windows" {
			// Try to determine if it's 32-bit or 64-bit on Windows
			exe, err := p.Exe()
			if err == nil && strings.Contains(strings.ToLower(exe), "syswow64") {
				arch = "x86"
			} else if err == nil && strings.Contains(strings.ToLower(exe), "system32") {
				arch = "x64"
			}
		}

		processes = append(processes, ProcessInfo{
			PID:     p.Pid,
			PPID:    ppid,
			Name:    name,
			Arch:    arch,
			User:    username,
			CmdLine: cmdline,
		})
	}

	return processes, nil
}

func formatProcessList(processes []ProcessInfo, verbose bool) string {
	if len(processes) == 0 {
		return "No processes found"
	}

	var result strings.Builder

	// Header
	if verbose {
		result.WriteString(fmt.Sprintf("%-8s %-8s %-30s %-8s %-20s %s\n", "PID", "PPID", "Name", "Arch", "User", "Command Line"))
		result.WriteString(strings.Repeat("-", 140) + "\n")
	} else {
		result.WriteString(fmt.Sprintf("%-8s %-8s %-30s %-8s %-20s\n", "PID", "PPID", "Name", "Arch", "User"))
		result.WriteString(strings.Repeat("-", 80) + "\n")
	}

	// Process rows
	for _, proc := range processes {
		user := proc.User
		if user == "" {
			user = "N/A"
		}

		if verbose {
			result.WriteString(fmt.Sprintf("%-8d %-8d %-30s %-8s %-20s %s\n",
				proc.PID, proc.PPID, proc.Name, proc.Arch, user, proc.CmdLine))
		} else {
			result.WriteString(fmt.Sprintf("%-8d %-8d %-30s %-8s %-20s\n",
				proc.PID, proc.PPID, proc.Name, proc.Arch, user))
		}
	}

	result.WriteString(fmt.Sprintf("\nTotal: %d processes\n", len(processes)))

	return result.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
