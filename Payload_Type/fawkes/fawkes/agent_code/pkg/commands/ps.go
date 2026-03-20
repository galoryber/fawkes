package commands

import (
	"encoding/json"
	"runtime"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/shirou/gopsutil/v3/process"
)

// perProcessTimeout is the maximum time to spend querying attributes for a
// single process. On Windows, p.Username() / p.Exe() / p.Cmdline() can hang
// indefinitely on protected system processes (csrss.exe, lsass.exe, etc.)
// because they require opening the process handle and querying tokens.
const perProcessTimeout = 2 * time.Second

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
	PID     int32  `json:"pid"`
	PPID    int32  `json:"ppid"`
	Name    string `json:"name"`
	Arch    string `json:"arch"`
	User    string `json:"user"`
	BinPath string `json:"bin_path"`
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

// processAttrs holds the expensive-to-query attributes of a process.
type processAttrs struct {
	username, cmdline, exe string
}

// queryProcessAttrs queries Username, Cmdline, and Exe with a timeout.
// On Windows, these calls can hang indefinitely on protected system processes
// (csrss.exe, lsass.exe, System, etc.) because the underlying Windows API calls
// (OpenProcess, GetTokenInformation, ReadProcessMemory) are blocking syscalls
// that cannot be interrupted by Go context cancellation.
func queryProcessAttrs(p *process.Process) processAttrs {
	ch := make(chan processAttrs, 1)
	go func() {
		u, _ := p.Username()
		c, _ := p.Cmdline()
		e, _ := p.Exe()
		ch <- processAttrs{u, c, e}
	}()
	select {
	case a := <-ch:
		return a
	case <-time.After(perProcessTimeout):
		// Goroutine may leak if stuck in a syscall, but this is acceptable
		// for an agent — it prevents the entire ps/process-tree from hanging.
		return processAttrs{}
	}
}

func getProcessList(args PsArgs) ([]ProcessInfo, error) {
	// Get all processes
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var processes []ProcessInfo
	filterLower := strings.ToLower(args.Filter)
	userFilterLower := strings.ToLower(args.User)

	for _, p := range procs {
		// Apply PID filter if specified
		if args.PID > 0 && p.Pid != args.PID {
			continue
		}

		// Name and Ppid are read from the process snapshot (fast, no syscall)
		name, err := p.Name()
		if err != nil {
			continue
		}

		// Apply name filter if specified
		if args.Filter != "" && !strings.Contains(strings.ToLower(name), filterLower) {
			continue
		}

		ppid, _ := p.Ppid()

		// Apply PPID filter if specified
		if args.PPID > 0 && ppid != args.PPID {
			continue
		}

		// Query expensive attributes with a per-process timeout to prevent
		// hangs on protected Windows processes
		attrs := queryProcessAttrs(p)

		// Apply user filter if specified
		if args.User != "" && !strings.Contains(strings.ToLower(attrs.username), userFilterLower) {
			continue
		}

		// Determine architecture
		arch := runtime.GOARCH
		if runtime.GOOS == "windows" {
			exeLower := strings.ToLower(attrs.exe)
			if strings.Contains(exeLower, "syswow64") {
				arch = "x86"
			} else if strings.Contains(exeLower, "system32") {
				arch = "x64"
			}
		}

		processes = append(processes, ProcessInfo{
			PID:     p.Pid,
			PPID:    ppid,
			Name:    name,
			Arch:    arch,
			User:    attrs.username,
			BinPath: attrs.exe,
			CmdLine: attrs.cmdline,
		})
	}

	return processes, nil
}
