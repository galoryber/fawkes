package commands

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestEDRProductDatabase(t *testing.T) {
	if len(knownEDRProducts) < 10 {
		t.Errorf("knownEDRProducts has %d entries, want at least 10", len(knownEDRProducts))
	}
	// Verify all products have required fields
	for _, p := range knownEDRProducts {
		if p.Name == "" {
			t.Error("EDR product with empty Name")
		}
		if p.Vendor == "" {
			t.Errorf("EDR product %q has empty Vendor", p.Name)
		}
		if len(p.Processes) == 0 {
			t.Errorf("EDR product %q has no process names", p.Name)
		}
		// All process names should be lowercase
		for _, proc := range p.Processes {
			if proc != strings.ToLower(proc) {
				t.Errorf("EDR product %q process %q is not lowercase", p.Name, proc)
			}
		}
	}
}

func TestDetectEDRProducts(t *testing.T) {
	// detectEDRProducts should not crash on any platform
	detections := detectEDRProducts()
	// Results vary by platform, but format should be consistent
	for _, d := range detections {
		if d.Name == "" {
			t.Error("Detection with empty Name")
		}
		if d.Status != "running" && d.Status != "installed" {
			t.Errorf("Detection %q has unexpected status %q", d.Name, d.Status)
		}
		if d.Platform != runtime.GOOS {
			t.Errorf("Detection %q platform=%q, want %q", d.Name, d.Platform, runtime.GOOS)
		}
	}
}

func TestSecurityInfoEDRAction(t *testing.T) {
	cmd := &SecurityInfoCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"edr"}`})
	if result.Status != "success" {
		t.Errorf("EDR action should succeed, got status=%q output=%q", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "EDR/Security Product Detection") {
		t.Error("EDR output missing header")
	}
	if !strings.Contains(result.Output, "products checked") {
		t.Error("EDR output missing summary line")
	}
}

func TestSecurityInfoEDRJSON(t *testing.T) {
	cmd := &SecurityInfoCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"edr"}`})
	// Output has text header + JSON array at the end. Find the JSON array.
	idx := strings.LastIndex(result.Output, "\n[")
	if idx < 0 {
		t.Fatal("Expected JSON array in output")
	}
	jsonPart := strings.TrimSpace(result.Output[idx:])
	var detections []edrDetection
	if err := json.Unmarshal([]byte(jsonPart), &detections); err != nil {
		t.Errorf("Failed to parse EDR JSON output: %v\nJSON: %s", err, jsonPart)
	}
}

func TestSecurityInfoDefaultAction(t *testing.T) {
	cmd := &SecurityInfoCommand{}
	// Empty params should default to "all" (existing behavior)
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Errorf("Default action should succeed, got status=%q", result.Status)
	}
	if !strings.Contains(result.Output, "Security Posture Report") {
		t.Error("Default action should show Security Posture Report")
	}
}

func TestGetRunningProcessNames(t *testing.T) {
	procs := getRunningProcessNames()
	if len(procs) == 0 {
		t.Error("getRunningProcessNames returned empty map — expected at least the current process")
	}
	// Verify no empty keys
	for name := range procs {
		if name == "" {
			t.Error("Empty process name in map")
		}
	}
}
