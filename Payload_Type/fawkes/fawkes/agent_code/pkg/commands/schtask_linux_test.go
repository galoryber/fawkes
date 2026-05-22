//go:build linux

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSchtaskLinux_Name(t *testing.T) {
	cmd := &SchtaskCommand{}
	if cmd.Name() != "schtask" {
		t.Errorf("expected 'schtask', got '%s'", cmd.Name())
	}
}

func TestSchtaskLinux_Description(t *testing.T) {
	cmd := &SchtaskCommand{}
	if !strings.Contains(cmd.Description(), "Linux") {
		t.Errorf("description should mention Linux, got '%s'", cmd.Description())
	}
}

func TestSchtaskLinux_EmptyParams(t *testing.T) {
	cmd := &SchtaskCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("expected error for empty params")
	}
}

func TestSchtaskLinux_InvalidJSON(t *testing.T) {
	cmd := &SchtaskCommand{}
	result := cmd.Execute(structs.Task{Params: "{bad"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
}

func TestSchtaskLinux_UnknownAction(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "invalid"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for unknown action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected unknown action message, got '%s'", result.Output)
	}
}

func TestSchtaskLinux_QueryNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "query"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty for query")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("expected name required message, got '%s'", result.Output)
	}
}

func TestSchtaskLinux_DeleteNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "delete"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty for delete")
	}
}

func TestSchtaskLinux_RunNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "run"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty for run")
	}
}

func TestSchtaskLinux_EnableNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "enable"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty for enable")
	}
}

func TestSchtaskLinux_DisableNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "disable"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty for disable")
	}
}

func TestSchtaskLinux_StopNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "stop"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty for stop")
	}
}

func TestSchtaskLinux_CreateNoProgram(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "create", Name: "test"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when program is empty for create")
	}
	if !strings.Contains(result.Output, "program is required") {
		t.Errorf("expected program required message, got '%s'", result.Output)
	}
}

func TestSchtaskLinux_CreateAtNoTime(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "create", Program: "/usr/bin/test", Trigger: "at"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when time is empty for at job creation")
	}
	if !strings.Contains(result.Output, "time is required") {
		t.Errorf("expected time required message, got '%s'", result.Output)
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

func TestParseCrontabLines(t *testing.T) {
	content := `# comment line
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin
*/5 * * * * /usr/bin/check-updates
0 2 * * * /usr/local/bin/backup.sh # nightly-backup
@reboot /usr/bin/startup-service
`
	entries := parseCrontabLines(content, "crontab(testuser)")

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	if !strings.Contains(entries[0].Name, "*/5 * * * *") {
		t.Errorf("entry 0 should contain schedule, got '%s'", entries[0].Name)
	}
	if !strings.Contains(entries[0].Name, "check-updates") {
		t.Errorf("entry 0 should contain command, got '%s'", entries[0].Name)
	}
	if entries[0].Type != "crontab" {
		t.Errorf("expected type 'crontab', got '%s'", entries[0].Type)
	}

	if !strings.Contains(entries[1].Name, "backup") {
		t.Errorf("entry 1 should contain backup, got '%s'", entries[1].Name)
	}
}

func TestParseCrontabLines_SystemCrontab(t *testing.T) {
	content := `17 *  * * *  root  cd / && run-parts --report /etc/cron.hourly
25 6  * * *  root  test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily
`
	entries := parseCrontabLines(content, "system(/etc/crontab)")

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	// System crontab has user field (6th field), command starts at field 7
	if strings.Contains(entries[0].Name, "root") {
		t.Errorf("system crontab entry should not include user 'root' in command portion, got '%s'", entries[0].Name)
	}
}

func TestParseCrontabLines_Empty(t *testing.T) {
	entries := parseCrontabLines("", "crontab(user)")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty content, got %d", len(entries))
	}
}

func TestParseCrontabLines_OnlyComments(t *testing.T) {
	content := "# m h  dom mon dow   command\n# no actual entries\n"
	entries := parseCrontabLines(content, "crontab(user)")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for comment-only content, got %d", len(entries))
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

func TestTriggerToSchedule(t *testing.T) {
	tests := []struct {
		trigger  string
		time     string
		expected string
	}{
		{"DAILY", "09:30", "30 09 * * *"},
		{"WEEKLY", "14:00", "00 14 * * 0"},
		{"MONTHLY", "06:00", "00 06 1 * *"},
		{"ONSTART", "", "@reboot"},
		{"", "12:00", "00 12 * * *"},
		{"DAILY", "", "0 0 * * *"},
	}

	for _, tt := range tests {
		result := triggerToSchedule(tt.trigger, tt.time)
		if result != tt.expected {
			t.Errorf("triggerToSchedule(%q, %q) = %q, want %q", tt.trigger, tt.time, result, tt.expected)
		}
	}
}

func TestMatchesCronEntry(t *testing.T) {
	tests := []struct {
		line     string
		name     string
		expected bool
	}{
		{"*/5 * * * * /usr/bin/check # mymarker", "mymarker", true},
		{"*/5 * * * * /usr/bin/mymarker-script", "mymarker", true},
		{"*/5 * * * * /usr/bin/other-script", "mymarker", false},
		{"# comment line", "anything", false},
		{"", "anything", false},
	}

	for _, tt := range tests {
		result := matchesCronEntry(tt.line, tt.name)
		if result != tt.expected {
			t.Errorf("matchesCronEntry(%q, %q) = %v, want %v", tt.line, tt.name, result, tt.expected)
		}
	}
}

func TestIsNumeric(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"123", true},
		{"0", true},
		{"abc", false},
		{"12a", false},
		{"", false},
	}

	for _, tt := range tests {
		result := isNumeric(tt.input)
		if result != tt.expected {
			t.Errorf("isNumeric(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestIsSystemCrontab(t *testing.T) {
	if !isSystemCrontab("system(/etc/crontab)") {
		t.Error("should detect /etc/crontab as system")
	}
	if !isSystemCrontab("cron.d(myfile)") {
		t.Error("should detect cron.d as system")
	}
	if isSystemCrontab("crontab(user)") {
		t.Error("should not detect user crontab as system")
	}
}

func TestSchtaskLinux_ListAction(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "list"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("list should succeed even with no entries, got '%s': %s", result.Status, result.Output)
	}
}
