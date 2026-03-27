//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

type ServiceCommand struct{}

func (c *ServiceCommand) Name() string {
	return "service"
}

func (c *ServiceCommand) Description() string {
	return "Manage Linux services via systemctl (list, query, start, stop, restart, create, delete, enable, disable)"
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
		return errorResult("Error: parameters required. Actions: list, query, start, stop, create, delete, enable, disable")
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return serviceListLinux()
	case "query":
		return serviceQueryLinux(args)
	case "start":
		return serviceCtl(args, "start")
	case "stop":
		return serviceCtl(args, "stop")
	case "restart":
		return serviceCtl(args, "restart")
	case "enable":
		return serviceCtl(args, "enable")
	case "create":
		return serviceCreateLinux(args)
	case "delete":
		return serviceDeleteLinux(args)
	case "disable":
		return serviceCtl(args, "disable")
	default:
		return errorf("Unknown action: %s. Use: list, query, start, stop, restart, create, delete, enable, disable", args.Action)
	}
}

type linuxServiceEntry struct {
	Name    string `json:"name"`
	Load    string `json:"load"`
	Active  string `json:"active"`
	Sub     string `json:"sub"`
	Desc    string `json:"description"`
	Enabled string `json:"enabled,omitempty"`
}

func serviceListLinux() structs.CommandResult {
	// Use systemctl to list all service units with their status
	out, err := execCmdTimeoutOutput("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend")
	if err != nil {
		return errorf("Error listing services: %v\n%s", err, string(out))
	}

	var entries []linuxServiceEntry
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// systemctl output format: UNIT LOAD ACTIVE SUB DESCRIPTION
		// Leading bullet/dot may be present
		line = strings.TrimLeft(line, "● ")
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := fields[0]
		// Only show .service units, strip suffix for cleaner output
		if !strings.HasSuffix(name, ".service") {
			continue
		}
		name = strings.TrimSuffix(name, ".service")

		desc := ""
		if len(fields) >= 5 {
			desc = strings.Join(fields[4:], " ")
		}

		entries = append(entries, linuxServiceEntry{
			Name:   name,
			Load:   fields[1],
			Active: fields[2],
			Sub:    fields[3],
			Desc:   desc,
		})
	}

	// Enrich with enabled/disabled status
	enabledOut, err := execCmdTimeoutOutput("systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend")
	if err == nil {
		enabledMap := make(map[string]string)
		for _, line := range strings.Split(strings.TrimSpace(string(enabledOut)), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				unitName := strings.TrimSuffix(fields[0], ".service")
				enabledMap[unitName] = fields[1]
			}
		}
		for i, e := range entries {
			if state, ok := enabledMap[e.Name]; ok {
				entries[i].Enabled = state
			}
		}
	}

	if len(entries) == 0 {
		return successResult("[]")
	}

	jsonBytes, err := json.Marshal(entries)
	if err != nil {
		return errorf("Error marshalling services: %v", err)
	}

	return successResult(string(jsonBytes))
}

func serviceQueryLinux(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for query action")
	}

	unitName := args.Name
	if !strings.HasSuffix(unitName, ".service") {
		unitName += ".service"
	}

	// Use systemctl show for machine-readable properties
	out, err := execCmdTimeoutOutput("systemctl", "show", unitName, "--no-pager")
	if err != nil {
		return errorf("Error querying service %s: %v\n%s", args.Name, err, string(out))
	}

	// Parse key=value pairs, extract the most relevant ones
	props := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			props[parts[0]] = parts[1]
		}
	}

	// Check if service exists
	loadState := props["LoadState"]
	if loadState == "not-found" {
		return errorf("Service '%s' not found", args.Name)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Service: %s\n\n", args.Name))

	writeField := func(label, key string) {
		if v, ok := props[key]; ok && v != "" && v != "[not set]" {
			sb.WriteString(fmt.Sprintf("  %-20s %s\n", label+":", v))
		}
	}

	writeField("Description", "Description")
	writeField("Load State", "LoadState")
	writeField("Active State", "ActiveState")
	writeField("Sub State", "SubState")
	writeField("Unit File State", "UnitFileState")
	writeField("Main PID", "MainPID")
	writeField("Exec Start", "ExecStart")
	writeField("Exec Reload", "ExecReload")
	writeField("Restart", "Restart")
	writeField("User", "User")
	writeField("Group", "Group")
	writeField("Memory Current", "MemoryCurrent")
	writeField("CPU Usage", "CPUUsageNSec")
	writeField("Tasks Current", "TasksCurrent")
	writeField("State Change", "StateChangeTimestamp")
	writeField("Active Enter", "ActiveEnterTimestamp")
	writeField("Active Exit", "ActiveExitTimestamp")

	// Also get the unit file path
	writeField("Fragment Path", "FragmentPath")

	// Try to get the unit file contents for inspection
	if fragPath := props["FragmentPath"]; fragPath != "" {
		unitContent, readErr := readServiceFile(fragPath)
		if readErr == nil && len(unitContent) > 0 {
			sb.WriteString(fmt.Sprintf("\nUnit file (%s):\n", fragPath))
			content := string(unitContent)
			structs.ZeroBytes(unitContent)
			if len(content) > 2000 {
				content = content[:2000] + "\n[TRUNCATED]"
			}
			sb.WriteString(content)
		}
	}

	return successResult(sb.String())
}

// readServiceFile reads a file and returns its contents (for reading unit files).
func readServiceFile(path string) ([]byte, error) {
	// Resolve symlinks to get the actual file
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}
	return os.ReadFile(resolved)
}

// buildSystemdUnit generates a systemd unit file from the provided arguments.
func buildSystemdUnit(args serviceArgs) string {
	description := args.Display
	if description == "" {
		description = args.Name
	}

	var sb strings.Builder
	sb.WriteString("[Unit]\n")
	sb.WriteString(fmt.Sprintf("Description=%s\n", description))
	sb.WriteString("After=network.target\n\n")
	sb.WriteString("[Service]\n")
	sb.WriteString(fmt.Sprintf("ExecStart=%s\n", args.BinPath))
	sb.WriteString("Restart=on-failure\n")
	sb.WriteString("RestartSec=5\n\n")
	sb.WriteString("[Install]\n")
	sb.WriteString("WantedBy=multi-user.target\n")
	return sb.String()
}

func serviceCreateLinux(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for service creation")
	}
	if args.BinPath == "" {
		return errorResult("Error: binpath is required for service creation")
	}

	unitName := args.Name
	if !strings.HasSuffix(unitName, ".service") {
		unitName += ".service"
	}

	unitPath := filepath.Join("/etc/systemd/system", unitName)

	// Check if service already exists
	if _, err := os.Stat(unitPath); err == nil {
		return errorf("Error: service unit file already exists at %s. Delete first or choose a different name.", unitPath)
	}

	unitContent := buildSystemdUnit(args)

	// Write the unit file
	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
		return errorf("Error writing unit file %s: %v", unitPath, err)
	}

	// Reload systemd to pick up the new unit
	if out, err := execCmdTimeout("systemctl", "daemon-reload"); err != nil {
		// Clean up the file if daemon-reload fails
		os.Remove(unitPath)
		return errorf("Error reloading systemd: %v\n%s", err, string(out))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Created systemd service '%s'\n", args.Name))
	sb.WriteString(fmt.Sprintf("    Unit file: %s\n", unitPath))
	sb.WriteString(fmt.Sprintf("    ExecStart: %s\n", args.BinPath))

	// Handle start type
	startType := strings.ToLower(args.Start)
	switch startType {
	case "auto":
		if out, err := execCmdTimeout("systemctl", "enable", unitName); err != nil {
			sb.WriteString(fmt.Sprintf("    Warning: enable failed: %v\n%s", err, string(out)))
		} else {
			sb.WriteString("    Start Type: Automatic (enabled)\n")
		}
	case "disabled":
		sb.WriteString("    Start Type: Disabled\n")
	default:
		sb.WriteString("    Start Type: Manual (demand)\n")
	}

	sb.WriteString("\n[*] Use 'service -action start -name " + args.Name + "' to start the service")
	return successResult(sb.String())
}

func serviceDeleteLinux(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for service deletion")
	}

	unitName := args.Name
	if !strings.HasSuffix(unitName, ".service") {
		unitName += ".service"
	}

	unitPath := filepath.Join("/etc/systemd/system", unitName)

	// Check if the unit file exists
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return errorf("Error: unit file not found at %s", unitPath)
	}

	var sb strings.Builder

	// Stop the service (best-effort, may already be stopped)
	if out, err := execCmdTimeout("systemctl", "stop", unitName); err == nil {
		sb.WriteString(fmt.Sprintf("[+] Stopped %s\n", args.Name))
	} else {
		sb.WriteString(fmt.Sprintf("[*] Stop: %s\n", strings.TrimSpace(string(out))))
	}

	// Disable the service (best-effort)
	if out, err := execCmdTimeout("systemctl", "disable", unitName); err == nil {
		sb.WriteString(fmt.Sprintf("[+] Disabled %s\n", args.Name))
	} else {
		sb.WriteString(fmt.Sprintf("[*] Disable: %s\n", strings.TrimSpace(string(out))))
	}

	// Remove the unit file
	if err := os.Remove(unitPath); err != nil {
		return errorf("Error removing unit file %s: %v", unitPath, err)
	}
	sb.WriteString(fmt.Sprintf("[+] Removed %s\n", unitPath))

	// Reload systemd
	if _, err := execCmdTimeout("systemctl", "daemon-reload"); err == nil {
		sb.WriteString("[+] Reloaded systemd daemon\n")
	}

	sb.WriteString(fmt.Sprintf("\n[+] Service '%s' deleted successfully", args.Name))
	return successResult(sb.String())
}

func serviceCtl(args serviceArgs, action string) structs.CommandResult {
	if args.Name == "" {
		return errorf("Error: name is required for %s action", action)
	}

	unitName := args.Name
	if !strings.HasSuffix(unitName, ".service") {
		unitName += ".service"
	}

	out, err := execCmdTimeout("systemctl", action, unitName)
	if err != nil {
		return errorf("Error: systemctl %s %s failed: %v\n%s", action, args.Name, err, string(out))
	}

	return successf("Successfully executed: systemctl %s %s\n%s", action, args.Name, strings.TrimSpace(string(out)))
}
