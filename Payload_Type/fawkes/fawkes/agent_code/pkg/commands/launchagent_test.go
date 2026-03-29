//go:build darwin

package commands

import (
	"encoding/json"
	"testing"
)

func TestLaunchAgentCommandName(t *testing.T) {
	assertCommandName(t, &LaunchAgentCommand{}, "launchagent")
}

func TestLaunchAgentCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &LaunchAgentCommand{})
}

func TestLaunchAgentEmptyParams(t *testing.T) {
	cmd := &LaunchAgentCommand{}
	result := cmd.Execute(mockTask("launchagent", ""))
	assertError(t, result)
}

func TestLaunchAgentInvalidJSON(t *testing.T) {
	cmd := &LaunchAgentCommand{}
	result := cmd.Execute(mockTask("launchagent", "not json"))
	assertError(t, result)
}

func TestLaunchAgentUnknownAction(t *testing.T) {
	cmd := &LaunchAgentCommand{}
	params, _ := json.Marshal(launchAgentArgs{Action: "invalid"})
	result := cmd.Execute(mockTask("launchagent", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "Unknown action")
}

func TestLaunchAgentInstallMissingLabel(t *testing.T) {
	cmd := &LaunchAgentCommand{}
	params, _ := json.Marshal(launchAgentArgs{Action: "install"})
	result := cmd.Execute(mockTask("launchagent", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "label is required")
}

func TestLaunchAgentRemoveMissingLabel(t *testing.T) {
	cmd := &LaunchAgentCommand{}
	params, _ := json.Marshal(launchAgentArgs{Action: "remove"})
	result := cmd.Execute(mockTask("launchagent", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "label is required")
}

func TestLaunchAgentListAction(t *testing.T) {
	cmd := &LaunchAgentCommand{}
	params, _ := json.Marshal(launchAgentArgs{Action: "list"})
	result := cmd.Execute(mockTask("launchagent", string(params)))
	assertSuccess(t, result)
	assertOutputContains(t, result, "macOS Persistence")
}

func TestLaunchAgentArgsUnmarshal(t *testing.T) {
	var args launchAgentArgs
	data := `{"action":"install","label":"com.test.agent","path":"/usr/bin/test","args":"-v -d","interval":300,"daemon":true}`
	if err := json.Unmarshal([]byte(data), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.Action != "install" {
		t.Errorf("Action = %q, want install", args.Action)
	}
	if args.Label != "com.test.agent" {
		t.Errorf("Label = %q, want com.test.agent", args.Label)
	}
	if args.Path != "/usr/bin/test" {
		t.Errorf("Path = %q, want /usr/bin/test", args.Path)
	}
	if args.Interval != 300 {
		t.Errorf("Interval = %d, want 300", args.Interval)
	}
	if !args.Daemon {
		t.Error("Daemon = false, want true")
	}
}

func TestGetPlistDirUserAgent(t *testing.T) {
	dir, err := getPlistDir(false)
	if err != nil {
		t.Fatalf("getPlistDir(false) failed: %v", err)
	}
	if dir == "" {
		t.Error("getPlistDir(false) returned empty string")
	}
	if dir == "/Library/LaunchDaemons" {
		t.Error("getPlistDir(false) should return user LaunchAgents dir, not system LaunchDaemons")
	}
}

func TestGetPlistDirDaemon(t *testing.T) {
	dir, err := getPlistDir(true)
	if err != nil {
		t.Fatalf("getPlistDir(true) failed: %v", err)
	}
	if dir != "/Library/LaunchDaemons" {
		t.Errorf("getPlistDir(true) = %q, want /Library/LaunchDaemons", dir)
	}
}
