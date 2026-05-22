//go:build linux

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSchtaskLinux_Description(t *testing.T) {
	cmd := &SchtaskCommand{}
	if !strings.Contains(cmd.Description(), "Linux") {
		t.Errorf("description should mention Linux, got '%s'", cmd.Description())
	}
}

func TestSchtaskLinux_CreateSystemdNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "create", Program: "/usr/bin/test", Trigger: "systemd"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty for systemd timer creation")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("expected name required message, got '%s'", result.Output)
	}
}

func TestParseSystemctlTimerOutput(t *testing.T) {
	output := `Thu 2026-05-22 09:00:00 CDT  1h 15min left  Thu 2026-05-22 07:30:00 CDT  14min ago  apt-daily.timer              apt-daily.service
n/a                          n/a            n/a                          n/a        fstrim.timer                 fstrim.service
`
	entries := parseSystemctlTimerOutput(output, "system")

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if !strings.Contains(entries[0].Name, "apt-daily.timer") {
		t.Errorf("entry 0 should contain apt-daily.timer, got '%s'", entries[0].Name)
	}
	if !strings.Contains(entries[0].Name, "apt-daily.service") {
		t.Errorf("entry 0 should contain activates service, got '%s'", entries[0].Name)
	}
	if entries[0].Type != "systemd-timer" {
		t.Errorf("expected type systemd-timer, got '%s'", entries[0].Type)
	}
	if entries[0].State != "waiting" {
		t.Errorf("expected state waiting, got '%s'", entries[0].State)
	}

	if entries[1].State != "inactive" {
		t.Errorf("fstrim should be inactive, got '%s'", entries[1].State)
	}
}

func TestParseSystemctlTimerOutput_Empty(t *testing.T) {
	entries := parseSystemctlTimerOutput("", "system")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty output, got %d", len(entries))
	}
}

func TestParseSystemctlShow(t *testing.T) {
	output := `Type=notify
Description=Daily apt download activities
LoadState=loaded
ActiveState=waiting
SubState=waiting
TimersCalendar={ OnCalendar=*-*-* 6,18:00:00 }
`
	props := parseSystemctlShow(output)

	if props["Type"] != "notify" {
		t.Errorf("expected Type=notify, got '%s'", props["Type"])
	}
	if props["LoadState"] != "loaded" {
		t.Errorf("expected LoadState=loaded, got '%s'", props["LoadState"])
	}
	if !strings.Contains(props["Description"], "apt download") {
		t.Errorf("expected Description to contain 'apt download', got '%s'", props["Description"])
	}
}
