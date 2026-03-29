//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestDrivesCommandName(t *testing.T) {
	assertCommandName(t, &DrivesCommand{}, "drives")
}

func TestDrivesCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &DrivesCommand{})
}

func TestDrivesExecute(t *testing.T) {
	cmd := &DrivesCommand{}
	result := cmd.Execute(mockTask("drives", ""))
	assertSuccess(t, result)
	// Should return JSON array with at least C:\
	var entries []driveEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("failed to parse drives output as JSON: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected at least one drive")
	}
	foundC := false
	for _, e := range entries {
		if e.Drive == "C:\\" {
			foundC = true
			if e.Type != "Fixed" {
				t.Errorf("C:\\ type = %q, want Fixed", e.Type)
			}
			if e.TotalGB <= 0 {
				t.Errorf("C:\\ TotalGB = %f, want > 0", e.TotalGB)
			}
		}
	}
	if !foundC {
		t.Error("expected to find C:\\ drive")
	}
}

func TestDriveEntryJSON(t *testing.T) {
	entry := driveEntry{
		Drive:   "C:\\",
		Type:    "Fixed",
		Label:   "Windows",
		FreeGB:  50.5,
		TotalGB: 256.0,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var parsed driveEntry
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed.Drive != "C:\\" {
		t.Errorf("Drive = %q, want C:\\", parsed.Drive)
	}
	if parsed.FreeGB != 50.5 {
		t.Errorf("FreeGB = %f, want 50.5", parsed.FreeGB)
	}
}
