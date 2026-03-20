//go:build darwin

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
	return "Manage macOS services via launchctl (list, query, start, stop, restart, create, delete, enable, disable)"
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
		return serviceListDarwin()
	case "query":
		return serviceQueryDarwin(args)
	case "start":
		return serviceStartDarwin(args)
	case "stop":
		return serviceStopDarwin(args)
	case "restart":
		return serviceRestartDarwin(args)
	case "enable":
		return serviceEnableDarwin(args)
	case "create":
		return serviceCreateDarwin(args)
	case "delete":
		return serviceDeleteDarwin(args)
	case "disable":
		return serviceDisableDarwin(args)
	default:
		return errorf("Unknown action: %s. Use: list, query, start, stop, restart, create, delete, enable, disable", args.Action)
	}
}

type darwinServiceEntry struct {
	PID    string `json:"pid"`
	Status string `json:"status"`
	Label  string `json:"label"`
	Domain string `json:"domain,omitempty"`
}

func serviceListDarwin() structs.CommandResult {
	// launchctl list outputs: PID\tStatus\tLabel
	out, err := execCmdTimeoutOutput("launchctl", "list")
	if err != nil {
		return errorf("Error listing services: %v\n%s", err, string(out))
	}

	var entries []darwinServiceEntry
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip header line
		if strings.HasPrefix(line, "PID") {
			continue
		}

		fields := strings.SplitN(line, "\t", 3)
		if len(fields) < 3 {
			continue
		}

		pid := fields[0]
		if pid == "-" {
			pid = ""
		}

		status := fields[1]
		label := fields[2]

		// Determine domain from label prefix
		domain := ""
		if strings.HasPrefix(label, "com.apple.") {
			domain = "system"
		}

		entries = append(entries, darwinServiceEntry{
			PID:    pid,
			Status: status,
			Label:  label,
			Domain: domain,
		})
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

func serviceQueryDarwin(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for query action")
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Service: %s\n\n", args.Name))

	// Try launchctl print for detailed info (macOS 10.10+)
	// Try system domain first, then gui domain
	var out []byte
	var err error

	// Try system domain
	out, err = execCmdTimeoutOutput("launchctl", "print", "system/"+args.Name)
	if err != nil {
		// Try user (gui) domain
		uid := fmt.Sprintf("%d", os.Getuid())
		out, err = execCmdTimeoutOutput("launchctl", "print", "gui/"+uid+"/"+args.Name)
		if err != nil {
			// Fallback to launchctl list <label>
			out, err = execCmdTimeoutOutput("launchctl", "list", args.Name)
			if err != nil {
				return errorf("Service '%s' not found or access denied: %v", args.Name, err)
			}
			sb.WriteString(string(out))
			sb.WriteString("\n")

			// Try to find the plist file
			plistPath := findPlistPath(args.Name)
			if plistPath != "" {
				sb.WriteString(fmt.Sprintf("Plist: %s\n", plistPath))
			}
			return successResult(sb.String())
		}
	}

	sb.WriteString(string(out))

	// Try to find the plist file for additional context
	plistPath := findPlistPath(args.Name)
	if plistPath != "" {
		sb.WriteString(fmt.Sprintf("\nPlist path: %s\n", plistPath))

		content, readErr := os.ReadFile(plistPath)
		if readErr == nil && len(content) > 0 {
			sb.WriteString("\nPlist contents:\n")
			text := string(content)
			if len(text) > 2000 {
				text = text[:2000] + "\n[TRUNCATED]"
			}
			sb.WriteString(text)
		}
	}

	return successResult(sb.String())
}

// findPlistPath searches common LaunchDaemon/LaunchAgent directories for a service plist
func findPlistPath(label string) string {
	plistName := label + ".plist"
	searchDirs := []string{
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
		"/System/Library/LaunchAgents",
	}

	// Also check user LaunchAgents
	if home, err := os.UserHomeDir(); err == nil {
		searchDirs = append(searchDirs, filepath.Join(home, "Library", "LaunchAgents"))
	}

	for _, dir := range searchDirs {
		path := filepath.Join(dir, plistName)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func serviceStartDarwin(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required to start a service")
	}

	// Try kickstart (more reliable for system services)
	out, err := execCmdTimeoutOutput("launchctl", "kickstart", "system/"+args.Name)
	if err != nil {
		// Fallback to bootstrap/load
		plistPath := findPlistPath(args.Name)
		if plistPath != "" {
			out, err = execCmdTimeoutOutput("launchctl", "load", plistPath)
			if err != nil {
				return errorf("Error starting service '%s': %v\n%s", args.Name, err, string(out))
			}
			return successf("Loaded service '%s' from %s", args.Name, plistPath)
		}

		// Try gui domain
		uid := fmt.Sprintf("%d", os.Getuid())
		out, err = execCmdTimeoutOutput("launchctl", "kickstart", "gui/"+uid+"/"+args.Name)
		if err != nil {
			return errorf("Error starting service '%s': %v\n%s", args.Name, err, string(out))
		}
	}

	return successf("Started service '%s'\n%s", args.Name, strings.TrimSpace(string(out)))
}

func serviceStopDarwin(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required to stop a service")
	}

	// Try kill in system domain
	out, err := execCmdTimeoutOutput("launchctl", "kill", "SIGTERM", "system/"+args.Name)
	if err != nil {
		// Try unload with plist path
		plistPath := findPlistPath(args.Name)
		if plistPath != "" {
			out, err = execCmdTimeoutOutput("launchctl", "unload", plistPath)
			if err != nil {
				return errorf("Error stopping service '%s': %v\n%s", args.Name, err, string(out))
			}
			return successf("Unloaded service '%s' from %s", args.Name, plistPath)
		}

		// Try gui domain
		uid := fmt.Sprintf("%d", os.Getuid())
		out, err = execCmdTimeoutOutput("launchctl", "kill", "SIGTERM", "gui/"+uid+"/"+args.Name)
		if err != nil {
			return errorf("Error stopping service '%s': %v\n%s", args.Name, err, string(out))
		}
	}

	return successf("Stopped service '%s'\n%s", args.Name, strings.TrimSpace(string(out)))
}

func serviceRestartDarwin(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required to restart a service")
	}

	// Use kickstart -k which kills the running instance and restarts it
	out, err := execCmdTimeoutOutput("launchctl", "kickstart", "-k", "system/"+args.Name)
	if err != nil {
		// Try gui domain
		uid := fmt.Sprintf("%d", os.Getuid())
		out, err = execCmdTimeoutOutput("launchctl", "kickstart", "-k", "gui/"+uid+"/"+args.Name)
		if err != nil {
			return errorf("Error restarting service '%s': %v\n%s", args.Name, err, string(out))
		}
	}

	return successf("Restarted service '%s'\n%s", args.Name, strings.TrimSpace(string(out)))
}

func serviceEnableDarwin(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required to enable a service")
	}

	// launchctl enable system/<label>
	out, err := execCmdTimeoutOutput("launchctl", "enable", "system/"+args.Name)
	if err != nil {
		// Try gui domain
		uid := fmt.Sprintf("%d", os.Getuid())
		out, err = execCmdTimeoutOutput("launchctl", "enable", "gui/"+uid+"/"+args.Name)
		if err != nil {
			return errorf("Error enabling service '%s': %v\n%s", args.Name, err, string(out))
		}
	}

	return successf("Enabled service '%s'\n%s", args.Name, strings.TrimSpace(string(out)))
}

// buildLaunchdPlist generates a launchd plist XML for the service.
func buildLaunchdPlist(label, binPath string, runAtLoad bool) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString("\n")
	sb.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`)
	sb.WriteString("\n")
	sb.WriteString(`<plist version="1.0">`)
	sb.WriteString("\n<dict>\n")
	sb.WriteString(fmt.Sprintf("\t<key>Label</key>\n\t<string>%s</string>\n", label))
	sb.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	sb.WriteString(fmt.Sprintf("\t\t<string>%s</string>\n", binPath))
	sb.WriteString("\t</array>\n")
	if runAtLoad {
		sb.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")
	}
	sb.WriteString("\t<key>KeepAlive</key>\n\t<true/>\n")
	sb.WriteString("</dict>\n</plist>\n")
	return sb.String()
}

func serviceCreateDarwin(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for service creation")
	}
	if args.BinPath == "" {
		return errorResult("Error: binpath is required for service creation")
	}

	// Determine plist location based on effective UID
	var plistDir string
	if os.Geteuid() == 0 {
		plistDir = "/Library/LaunchDaemons"
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return errorf("Error getting home directory: %v", err)
		}
		plistDir = filepath.Join(home, "Library", "LaunchAgents")
	}

	plistPath := filepath.Join(plistDir, args.Name+".plist")

	// Check if plist already exists
	if _, err := os.Stat(plistPath); err == nil {
		return errorf("Error: plist already exists at %s. Delete first or choose a different name.", plistPath)
	}

	// Ensure directory exists
	if err := os.MkdirAll(plistDir, 0755); err != nil {
		return errorf("Error creating directory %s: %v", plistDir, err)
	}

	runAtLoad := strings.ToLower(args.Start) == "auto"
	plistContent := buildLaunchdPlist(args.Name, args.BinPath, runAtLoad)

	// Write the plist file
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return errorf("Error writing plist %s: %v", plistPath, err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Created launchd service '%s'\n", args.Name))
	sb.WriteString(fmt.Sprintf("    Plist: %s\n", plistPath))
	sb.WriteString(fmt.Sprintf("    Binary: %s\n", args.BinPath))

	if os.Geteuid() == 0 {
		sb.WriteString("    Domain: system (LaunchDaemon)\n")
	} else {
		sb.WriteString("    Domain: user (LaunchAgent)\n")
	}

	// Load the service
	out, err := execCmdTimeoutOutput("launchctl", "load", plistPath)
	if err != nil {
		sb.WriteString(fmt.Sprintf("    Warning: load failed: %v\n%s", err, string(out)))
		sb.WriteString("    [*] Manually load with: launchctl load " + plistPath)
	} else {
		sb.WriteString("    Status: Loaded\n")
	}

	startType := "Manual"
	if runAtLoad {
		startType = "Automatic (RunAtLoad)"
	}
	if strings.ToLower(args.Start) == "disabled" {
		startType = "Disabled"
	}
	sb.WriteString(fmt.Sprintf("    Start Type: %s\n", startType))

	return successResult(sb.String())
}

func serviceDeleteDarwin(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required for service deletion")
	}

	// Find the plist file
	plistPath := findPlistPath(args.Name)
	if plistPath == "" {
		return errorf("Error: plist not found for '%s'. Searched LaunchDaemons and LaunchAgents directories.", args.Name)
	}

	var sb strings.Builder

	// Unload the service (best-effort)
	if out, err := execCmdTimeoutOutput("launchctl", "unload", plistPath); err == nil {
		sb.WriteString(fmt.Sprintf("[+] Unloaded %s\n", args.Name))
	} else {
		sb.WriteString(fmt.Sprintf("[*] Unload: %s\n", strings.TrimSpace(string(out))))
	}

	// Remove the plist file
	if err := os.Remove(plistPath); err != nil {
		return errorf("Error removing plist %s: %v", plistPath, err)
	}
	sb.WriteString(fmt.Sprintf("[+] Removed %s\n", plistPath))
	sb.WriteString(fmt.Sprintf("\n[+] Service '%s' deleted successfully", args.Name))

	return successResult(sb.String())
}

func serviceDisableDarwin(args serviceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name is required to disable a service")
	}

	// launchctl disable system/<label>
	out, err := execCmdTimeoutOutput("launchctl", "disable", "system/"+args.Name)
	if err != nil {
		// Try gui domain
		uid := fmt.Sprintf("%d", os.Getuid())
		out, err = execCmdTimeoutOutput("launchctl", "disable", "gui/"+uid+"/"+args.Name)
		if err != nil {
			return errorf("Error disabling service '%s': %v\n%s", args.Name, err, string(out))
		}
	}

	return successf("Disabled service '%s'\n%s", args.Name, strings.TrimSpace(string(out)))
}
