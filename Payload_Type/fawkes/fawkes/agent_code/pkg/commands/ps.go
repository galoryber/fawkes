package commands

import (
	"encoding/json"
	"strconv"
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

// PsArgs represents the arguments for ps command
type PsArgs struct {
	Verbose bool   `json:"verbose"`
	Filter  string `json:"filter"`
	PID     int32  `json:"pid"`
	PPID    int32  `json:"ppid"` // filter by parent PID
	User    string `json:"user"` // filter by username (substring, case-insensitive)
}

// ProcessInfo represents process information collected from the OS
type ProcessInfo struct {
	PID            int32  `json:"pid"`
	PPID           int32  `json:"ppid"`
	Name           string `json:"name"`
	Arch           string `json:"arch"`
	User           string `json:"user"`
	BinPath        string `json:"bin_path"`
	CmdLine        string `json:"cmdline,omitempty"`
	IntegrityLevel int    `json:"integrity_level,omitempty"` // Windows: 0=untrusted, 1=low, 2=medium, 3=high, 4=system
	StartTime      int64  `json:"start_time,omitempty"`      // Unix epoch seconds
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

	processes, err := getProcessList(args)
	if err != nil {
		return errorf("Error listing processes: %v", err)
	}

	// Build Mythic ProcessEntry slice for process browser integration
	mythicProcs := make([]structs.ProcessEntry, len(processes))
	for i, p := range processes {
		mythicProcs[i] = structs.ProcessEntry{
			ProcessID:       int(p.PID),
			ParentProcessID: int(p.PPID),
			Architecture:    p.Arch,
			Name:            p.Name,
			User:            p.User,
			BinPath:         p.BinPath,
			CommandLine:     p.CmdLine,
			IntegrityLevel:  p.IntegrityLevel,
			StartTime:       p.StartTime,
		}
	}

	// Return JSON for the browser script to render as a table
	jsonBytes, err := json.Marshal(mythicProcs)
	if err != nil {
		return errorf("Error marshalling process list: %v", err)
	}

	return structs.CommandResult{
		Output:    string(jsonBytes),
		Status:    "success",
		Completed: true,
		Processes: &mythicProcs,
	}
}

// getProcessList is implemented in platform-specific files:
// - ps_list.go (Linux/macOS — uses gopsutil)
// - ps_list_windows.go (Windows — uses direct CreateToolhelp32Snapshot API)
