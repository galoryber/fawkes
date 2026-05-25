//go:build windows
// +build windows

package commands

import (
	"testing"
)

func TestWinHijackTrigger_MissingTriggerType(t *testing.T) {
	result := winHijackTrigger(privescCheckArgs{Action: "hijack-trigger"})
	if result.Status != "error" {
		t.Errorf("Expected error for missing trigger type, got %s", result.Status)
	}
	if result.Output == "" {
		t.Error("Expected error message")
	}
}

func TestWinHijackTrigger_UnknownTriggerType(t *testing.T) {
	result := winHijackTrigger(privescCheckArgs{
		Action:  "hijack-trigger",
		Trigger: "invalid",
	})
	if result.Status != "error" {
		t.Errorf("Expected error for unknown trigger type, got %s", result.Status)
	}
	if result.Output == "" {
		t.Error("Expected error message")
	}
}

func TestHijackTriggerRestart_MissingServiceName(t *testing.T) {
	result := hijackTriggerRestart(privescCheckArgs{
		Action:  "hijack-trigger",
		Trigger: "restart",
	})
	if result.Status != "error" {
		t.Errorf("Expected error for missing service_name, got %s", result.Status)
	}
}

func TestHijackTriggerSpawn_MissingSource(t *testing.T) {
	result := hijackTriggerSpawn(privescCheckArgs{
		Action:  "hijack-trigger",
		Trigger: "spawn",
	})
	if result.Status != "error" {
		t.Errorf("Expected error for missing source, got %s", result.Status)
	}
}

func TestHijackTriggerSpawn_NonexistentExe(t *testing.T) {
	result := hijackTriggerSpawn(privescCheckArgs{
		Action:  "hijack-trigger",
		Trigger: "spawn",
		Source:  `C:\nonexistent\path\to\exe.exe`,
	})
	if result.Status != "error" {
		t.Errorf("Expected error for nonexistent executable, got %s", result.Status)
	}
}
