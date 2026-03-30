//go:build darwin
// +build darwin

package commands

import (
	"encoding/json"
	"testing"
)

func TestPrivescCheckCommandName(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	assertCommandName(t, cmd, "privesc-check")
}

func TestPrivescCheckCommandDescription(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	assertCommandHasDescription(t, cmd)
}

func TestPrivescCheckInvalidJSON(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := mockTask("privesc-check", "not valid json")
	result := cmd.Execute(task)
	assertError(t, result)
	assertOutputContains(t, result, "Error parsing")
}

func TestPrivescCheckUnknownAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	params, _ := json.Marshal(map[string]string{"action": "nonexistent"})
	task := mockTask("privesc-check", string(params))
	result := cmd.Execute(task)
	assertError(t, result)
	assertOutputContains(t, result, "Unknown action")
}

func TestPrivescCheckSIPAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	params, _ := json.Marshal(map[string]string{"action": "sip"})
	task := mockTask("privesc-check", string(params))
	result := cmd.Execute(task)
	// SIP check calls csrutil which should work on macOS
	assertSuccess(t, result)
}

func TestPrivescCheckSUIDAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	params, _ := json.Marshal(map[string]string{"action": "suid"})
	task := mockTask("privesc-check", string(params))
	result := cmd.Execute(task)
	// SUID scan should succeed (may find binaries or not)
	assertSuccess(t, result)
}

func TestPrivescCheckWritableAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	params, _ := json.Marshal(map[string]string{"action": "writable"})
	task := mockTask("privesc-check", string(params))
	result := cmd.Execute(task)
	assertSuccess(t, result)
}

func TestPrivescCheckTCCAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	params, _ := json.Marshal(map[string]string{"action": "tcc"})
	task := mockTask("privesc-check", string(params))
	result := cmd.Execute(task)
	// TCC check accesses the TCC database — should succeed or give meaningful error
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status: %s", result.Status)
	}
}

func TestPrivescCheckDylibAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	params, _ := json.Marshal(map[string]string{"action": "dylib"})
	task := mockTask("privesc-check", string(params))
	result := cmd.Execute(task)
	assertSuccess(t, result)
}

func TestPrivescCheckLaunchDaemonsAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	params, _ := json.Marshal(map[string]string{"action": "launchdaemons"})
	task := mockTask("privesc-check", string(params))
	result := cmd.Execute(task)
	assertSuccess(t, result)
}

func TestPrivescCheckAllAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	params, _ := json.Marshal(map[string]string{"action": "all"})
	task := mockTask("privesc-check", string(params))
	result := cmd.Execute(task)
	assertSuccess(t, result)
}

func TestPrivescCheckDefaultAction(t *testing.T) {
	// Empty params should default to "all"
	cmd := &PrivescCheckCommand{}
	task := mockTask("privesc-check", "{}")
	result := cmd.Execute(task)
	assertSuccess(t, result)
}
