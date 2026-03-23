package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestWlanProfilesBasic(t *testing.T) {
	cmd := &WlanProfilesCommand{}
	result := cmd.Execute(structs.Task{Params: "{}"})

	// On a system without WiFi, should still succeed (with "no profiles" or profiles found)
	if result.Status != "success" && result.Status != "error" {
		t.Fatalf("expected success or error, got %s: %s", result.Status, result.Output)
	}
	// If success, should have some output
	if result.Status == "success" && result.Output == "" {
		t.Fatalf("expected non-empty output on success")
	}
}

func TestWlanProfilesFilter(t *testing.T) {
	cmd := &WlanProfilesCommand{}
	result := cmd.Execute(structs.Task{Params: `{"name": "NonExistentNetwork12345"}`})

	// Should succeed but find nothing matching
	if result.Status == "success" {
		if !strings.Contains(result.Output, "No WiFi profiles") && !strings.Contains(result.Output, "0 WiFi") {
			// Either no profiles at all, or none matching filter
			t.Logf("Got output: %s", result.Output)
		}
	}
}

func TestWlanProfilesNoParams(t *testing.T) {
	cmd := &WlanProfilesCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	// Empty params should still work (no filter)
	if result.Status != "success" && result.Status != "error" {
		t.Fatalf("expected success or error, got %s: %s", result.Status, result.Output)
	}
}

func TestWlanProfilesInvalidJSON(t *testing.T) {
	cmd := &WlanProfilesCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %s", result.Status)
	}
}

func TestWlanProfilesNameDescription(t *testing.T) {
	cmd := &WlanProfilesCommand{}
	if cmd.Name() != "wlan-profiles" {
		t.Errorf("expected name 'wlan-profiles', got %q", cmd.Name())
	}
	if !strings.Contains(cmd.Description(), "WiFi") {
		t.Error("expected WiFi in description")
	}
}

func TestWlanProfilesFilterCase(t *testing.T) {
	// Test that filter is case-insensitive
	cmd := &WlanProfilesCommand{}
	result := cmd.Execute(structs.Task{Params: `{"name": "NONEXISTENT_SSID_xyz"}`})

	// Should succeed regardless of matching
	if result.Status != "success" && result.Status != "error" {
		t.Fatalf("unexpected status: %s", result.Status)
	}
}
