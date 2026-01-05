package commands

import (
	"encoding/json"
	"fmt"
	"os/exec"
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
			// If not JSON, treat as filter string
			// Check if it starts with -v for verbose
			if strings.HasPrefix(task.Params, "-v ") {
				args.Verbose = true
				args.Filter = strings.TrimSpace(task.Params[3:])
			} else if task.Params == "-v" {
				args.Verbose = true
			} else {
				args.Filter = strings.TrimSpace(task.Params)
			}
		}
	}

	processes, err := getProcessList(args.Filter)
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

func getProcessList(filter string) ([]ProcessInfo, error) {
	// Get all processes
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var processes []ProcessInfo
	filterLower := strings.ToLower(filter)

	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}

		// Apply filter if specified
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
			cmdline := proc.CmdLine
			if len(cmdline) > 60 {
				cmdline = cmdline[:57] + "..."
			}
			result.WriteString(fmt.Sprintf("%-8d %-8d %-30s %-8s %-20s %s\n",
				proc.PID, proc.PPID, truncate(proc.Name, 30), proc.Arch, truncate(user, 20), cmdline))
		} else {
			result.WriteString(fmt.Sprintf("%-8d %-8d %-30s %-8s %-20s\n",
				proc.PID, proc.PPID, truncate(proc.Name, 30), proc.Arch, truncate(user, 20)))
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
}

// ProcessInfo represents process information
type ProcessInfo struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
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
			// If not JSON, treat as filter string
			// Check if it starts with -v for verbose
			if strings.HasPrefix(task.Params, "-v ") {
				args.Verbose = true
				args.Filter = strings.TrimSpace(task.Params[3:])
			} else if task.Params == "-v" {
				args.Verbose = true
			} else {
				args.Filter = strings.TrimSpace(task.Params)
			}
		}
	}

	var processes []ProcessInfo
	var err error

	if runtime.GOOS == "windows" {
		processes, err = getWindowsProcesses(args.Filter)
	} else {
		processes, err = getUnixProcesses(args.Filter)
	}

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

func getWindowsProcesses(filter string) ([]ProcessInfo, error) {
	// Use PowerShell to get process information with better formatting
	psScript := `Get-Process | Select-Object Id,@{Name='ParentProcessId';Expression={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").ParentProcessId}},ProcessName,@{Name='UserName';Expression={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner().User}},Path,CommandLine | ConvertTo-Json -Compress`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Fallback to simpler method using WMIC
		return getWindowsProcessesWMIC(filter)
	}

	var rawProcesses []map[string]interface{}
	if err := json.Unmarshal(output, &rawProcesses); err != nil {
		// Single process returns as object, not array
		var singleProcess map[string]interface{}
		if err := json.Unmarshal(output, &singleProcess); err != nil {
			return getWindowsProcessesWMIC(filter)
		}
		rawProcesses = []map[string]interface{}{singleProcess}
	}

	var processes []ProcessInfo
	filterLower := strings.ToLower(filter)

	for _, proc := range rawProcesses {
		name := getStringValue(proc, "ProcessName")

		// Apply filter if specified
		if filter != "" && !strings.Contains(strings.ToLower(name), filterLower) {
			continue
		}

		pid := getIntValue(proc, "Id")
		ppid := getIntValue(proc, "ParentProcessId")

		// Determine architecture from path
		arch := "x64"
		if path, ok := proc["Path"].(string); ok && strings.Contains(strings.ToLower(path), "syswow64") {
			arch = "x86"
		}

		processes = append(processes, ProcessInfo{
			PID:     pid,
			PPID:    ppid,
			Name:    name,
			Arch:    arch,
			User:    getStringValue(proc, "UserName"),
			CmdLine: getStringValue(proc, "CommandLine"),
		})
	}

	return processes, nil
}

func getWindowsProcessesWMIC(filter string) ([]ProcessInfo, error) {
	cmd := exec.Command("wmic", "process", "get", "ProcessId,ParentProcessId,Name,ExecutablePath", "/format:csv")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var processes []ProcessInfo
	filterLower := strings.ToLower(filter)

	for i, line := range lines {
		if i < 2 || strings.TrimSpace(line) == "" {
			continue // Skip headers and empty lines
		}

		fields := strings.Split(line, ",")
		if len(fields) < 4 {
			continue
		}

		name := strings.TrimSpace(fields[3])

		// Apply filter if specified
		if filter != "" && !strings.Contains(strings.ToLower(name), filterLower) {
			continue
		}

		pid, _ := strconv.Atoi(strings.TrimSpace(fields[4]))
		ppid, _ := strconv.Atoi(strings.TrimSpace(fields[2]))

		arch := "x64"
		if len(fields) > 1 {
			if path := strings.TrimSpace(fields[1]); strings.Contains(strings.ToLower(path), "syswow64") {
				arch = "x86"
			}
		}

		processes = append(processes, ProcessInfo{
			PID:  pid,
			PPID: ppid,
			Name: name,
			Arch: arch,
			User: "",
		})
	}

	return processes, nil
}

func getUnixProcesses(filter string) ([]ProcessInfo, error) {
	cmd := exec.Command("ps", "-eo", "pid,ppid,user,comm,args")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var processes []ProcessInfo
	filterLower := strings.ToLower(filter)

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // Skip header and empty lines
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		user := fields[2]
		name := fields[3]
		cmdline := ""
		if len(fields) > 4 {
			cmdline = strings.Join(fields[4:], " ")
		}

		// Apply filter if specified
		if filter != "" && !strings.Contains(strings.ToLower(name), filterLower) {
			continue
		}

		processes = append(processes, ProcessInfo{
			PID:     pid,
			PPID:    ppid,
			Name:    name,
			Arch:    runtime.GOARCH,
			User:    user,
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
			cmdline := proc.CmdLine
			if len(cmdline) > 60 {
				cmdline = cmdline[:57] + "..."
			}
			result.WriteString(fmt.Sprintf("%-8d %-8d %-30s %-8s %-20s %s\n",
				proc.PID, proc.PPID, truncate(proc.Name, 30), proc.Arch, truncate(user, 20), cmdline))
		} else {
			result.WriteString(fmt.Sprintf("%-8d %-8d %-30s %-8s %-20s\n",
				proc.PID, proc.PPID, truncate(proc.Name, 30), proc.Arch, truncate(user, 20)))
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

func getStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok && val != nil {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getIntValue(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok && val != nil {
		switch v := val.(type) {
		case float64:
			return int(v)
		case int:
			return v
		case string:
			i, _ := strconv.Atoi(v)
			return i
		}
	}
	return 0
}
