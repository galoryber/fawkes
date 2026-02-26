package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestDriversName(t *testing.T) {
	cmd := &DriversCommand{}
	if cmd.Name() != "drivers" {
		t.Errorf("expected 'drivers', got '%s'", cmd.Name())
	}
}

func TestDriversDescription(t *testing.T) {
	cmd := &DriversCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestDriversExecuteNoParams(t *testing.T) {
	cmd := &DriversCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	// Should work without params (no filter)
	if result.Status == "error" && !strings.Contains(result.Output, "Error") {
		t.Errorf("unexpected error status without actual error: %s", result.Output)
	}
	if !result.Completed {
		t.Error("expected completed=true")
	}
}

func TestDriversExecuteWithFilter(t *testing.T) {
	cmd := &DriversCommand{}
	params, _ := json.Marshal(driversArgs{Filter: "nonexistent_driver_xyz"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Filter should work — may return 0 matches
	if !result.Completed {
		t.Error("expected completed=true")
	}
}

func TestDriversExecuteInvalidJSON(t *testing.T) {
	cmd := &DriversCommand{}
	// Invalid JSON should be treated as plain filter string
	result := cmd.Execute(structs.Task{Params: "somefilter"})
	if !result.Completed {
		t.Error("expected completed=true")
	}
}

func TestDriversFormatOutput(t *testing.T) {
	cmd := &DriversCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status == "success" {
		if !strings.Contains(result.Output, "Loaded Drivers/Modules") {
			t.Error("output should contain header")
		}
		if !strings.Contains(result.Output, "Name") {
			t.Error("output should contain column headers")
		}
	}
}

func TestDriverInfoStruct(t *testing.T) {
	d := DriverInfo{
		Name:   "test_driver",
		Path:   "/path/to/driver",
		Status: "loaded",
		Size:   12345,
	}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var d2 DriverInfo
	if err := json.Unmarshal(data, &d2); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if d2.Name != "test_driver" || d2.Size != 12345 {
		t.Error("round-trip failed")
	}
}
