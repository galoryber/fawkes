//go:build darwin
// +build darwin

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type EtwCommand struct{}

func (c *EtwCommand) Name() string {
	return "etw"
}

func (c *EtwCommand) Description() string {
	return "Enumerate macOS unified logging categories and detect security agents"
}

type etwParams struct {
	Action      string `json:"action"`
	SessionName string `json:"session_name"` // reused: log predicate filter
	Provider    string `json:"provider"`     // reused: subsystem filter
}

func (c *EtwCommand) Execute(task structs.Task) structs.CommandResult {
	var params etwParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.Action == "" {
		params.Action = "categories"
	}

	switch params.Action {
	case "categories":
		return logCategories(params.Provider)
	case "agents":
		return detectSecurityAgents()
	case "audit-status":
		return macAuditStatus()
	default:
		return errorf("Unknown action: %s (use categories, agents, audit-status)", params.Action)
	}
}

// logCategories lists unified logging subsystems and categories
func logCategories(subsystem string) structs.CommandResult {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var cmdArgs []string
	if subsystem != "" {
		// Show recent entries for a specific subsystem
		cmdArgs = []string{"show", "--predicate", fmt.Sprintf("subsystem == '%s'", subsystem), "--last", "1m", "--style", "compact"}
	} else {
		// List security-relevant subsystems by querying recent security logs
		cmdArgs = []string{"show", "--predicate", "category == 'security' OR subsystem CONTAINS 'security' OR subsystem CONTAINS 'opendirectory'", "--last", "5m", "--style", "compact"}
	}

	cmd := exec.CommandContext(ctx, "log", cmdArgs...)
	output, err := cmd.CombinedOutput()

	result := "[+] macOS Unified Logging\n"
	if subsystem != "" {
		result += fmt.Sprintf("Subsystem: %s\n", subsystem)
	} else {
		result += "Security-related log entries (last 5 minutes)\n"
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result += "[!] Query timed out (30s limit)\n"
		} else {
			result += fmt.Sprintf("Error: %v\n", err)
		}
	}

	if len(output) > 0 {
		lines := strings.Split(string(output), "\n")
		if len(lines) > 100 {
			result += strings.Join(lines[:100], "\n")
			result += fmt.Sprintf("\n... (%d more lines truncated)", len(lines)-100)
		} else {
			result += string(output)
		}
	} else {
		result += "No log entries found"
	}

	return successResult(result)
}

// macSecurityAgent describes a known macOS security agent
type macSecurityAgent struct {
	Name        string
	ProcessName []string
	AppPath     []string
}

var knownMacAgents = []macSecurityAgent{
	{"CrowdStrike Falcon", []string{"falcond", "falcon-sensor"}, []string{"/Library/CS", "/Applications/Falcon.app"}},
	{"SentinelOne", []string{"SentinelAgent", "sentineld"}, []string{"/Library/Sentinel", "/opt/sentinelone"}},
	{"Carbon Black", []string{"cbdaemon", "cbagentd", "CbDefense"}, []string{"/Applications/CarbonBlack", "/opt/carbonblack"}},
	{"Jamf Protect", []string{"JamfProtect"}, []string{"/Library/Application Support/JamfProtect"}},
	{"Jamf Connect", []string{"JamfConnect"}, []string{"/Library/Application Support/JamfConnect"}},
	{"osquery", []string{"osqueryd"}, []string{"/opt/osquery", "/var/osquery"}},
	{"Elastic Agent", []string{"elastic-agent"}, []string{"/Library/Elastic/Agent"}},
	{"Sophos", []string{"SophosScanD", "SophosAntiVirus"}, []string{"/Library/Sophos Anti-Virus"}},
	{"ESET", []string{"esets_daemon"}, []string{"/Library/Application Support/com.eset.remoteadministrator.agent"}},
	{"Kaspersky", []string{"kav", "klnagent"}, []string{"/Library/Application Support/Kaspersky Lab"}},
	{"Norton", []string{"Norton360"}, []string{"/Applications/Norton 360.app"}},
	{"Malwarebytes", []string{"Malwarebytes"}, []string{"/Library/Application Support/Malwarebytes"}},
	{"Little Snitch", []string{"Little Snitch Agent"}, []string{"/Library/Little Snitch"}},
	{"Lulu", []string{"LuLu"}, []string{"/Library/Objective-See/LuLu"}},
	{"BlockBlock", []string{"BlockBlock"}, []string{"/Library/Objective-See/BlockBlock"}},
	{"Oversight", []string{"OverSight"}, []string{"/Library/Objective-See/OverSight"}},
	{"Santa", []string{"santad", "santa-driver"}, []string{"/usr/local/bin/santactl"}},
}

// detectSecurityAgents checks for running security agents on macOS
func detectSecurityAgents() structs.CommandResult {
	type agentResult struct {
		Name      string `json:"name"`
		Status    string `json:"status"`
		Process   string `json:"process,omitempty"`
		PID       string `json:"pid,omitempty"`
		InstallAt string `json:"install_path,omitempty"`
	}

	var results []agentResult

	// Get running processes via ps
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ps", "-axo", "pid,comm")
	output, err := cmd.CombinedOutput()
	runningProcs := make(map[string]string) // comm -> pid
	if err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pid := fields[0]
				comm := filepath.Base(fields[len(fields)-1])
				runningProcs[comm] = pid
			}
		}
	}

	for _, agent := range knownMacAgents {
		found := false
		var r agentResult
		r.Name = agent.Name

		// Check running processes
		for _, procName := range agent.ProcessName {
			if pid, ok := runningProcs[procName]; ok {
				r.Status = "running"
				r.Process = procName
				r.PID = pid
				found = true
				break
			}
		}

		// Check install paths
		if !found {
			for _, path := range agent.AppPath {
				if _, err := os.Stat(path); err == nil {
					r.Status = "installed"
					r.InstallAt = path
					found = true
					break
				}
			}
		}

		if found {
			results = append(results, r)
		}
	}

	if len(results) == 0 {
		return successResult(`{"agents":[],"message":"No known security agents detected"}`)
	}

	out, err := json.MarshalIndent(map[string]interface{}{
		"agents": results,
		"total":  len(results),
	}, "", "  ")
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}

	return successResult(string(out))
}

// macAuditStatus shows the current audit subsystem status
func macAuditStatus() structs.CommandResult {
	var result strings.Builder
	result.WriteString("[+] macOS Audit Status\n")

	// Check OpenBSM audit status
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "audit", "-c")
	output, err := cmd.CombinedOutput()
	if err == nil {
		result.WriteString(fmt.Sprintf("OpenBSM: %s\n", strings.TrimSpace(string(output))))
	}

	// Read audit_control
	data, err := os.ReadFile("/etc/security/audit_control")
	if err == nil {
		result.WriteString("\n--- /etc/security/audit_control ---\n")
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				result.WriteString(trimmed + "\n")
			}
		}
	}

	// Check System Integrity Protection status
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	cmd2 := exec.CommandContext(ctx2, "csrutil", "status")
	output2, err2 := cmd2.CombinedOutput()
	if err2 == nil {
		result.WriteString(fmt.Sprintf("\nSIP: %s", strings.TrimSpace(string(output2))))
	}

	return successResult(result.String())
}
