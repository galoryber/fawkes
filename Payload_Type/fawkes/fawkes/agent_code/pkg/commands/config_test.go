package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestConfigName(t *testing.T) {
	cmd := &ConfigCommand{}
	if cmd.Name() != "config" {
		t.Errorf("Expected 'config', got '%s'", cmd.Name())
	}
}

func TestConfigDescription(t *testing.T) {
	cmd := &ConfigCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestConfigExecuteWithoutAgent(t *testing.T) {
	cmd := &ConfigCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("Expected error when Execute called without agent")
	}
	if !strings.Contains(result.Output, "requires agent context") {
		t.Errorf("Expected agent context error, got: %s", result.Output)
	}
}

func newTestAgent() *structs.Agent {
	return &structs.Agent{
		PayloadUUID:   "test-uuid-1234",
		Host:          "testhost",
		User:          "testuser",
		OS:            "linux",
		Architecture:  "amd64",
		PID:           12345,
		ProcessName:   "agent",
		InternalIP:    "192.168.1.100",
		Integrity:     3,
		SleepInterval: 30,
		Jitter:        20,
	}
}

func TestConfigShowDefault(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	result := cmd.ExecuteWithAgent(structs.Task{Params: ""}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Agent Configuration") {
		t.Errorf("Expected header, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "test-uuid-1234") {
		t.Errorf("Expected payload UUID, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "30") {
		t.Errorf("Expected sleep interval, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "20%") {
		t.Errorf("Expected jitter, got: %s", result.Output)
	}
}

func TestConfigShowExplicit(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "show"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestConfigBadJSON(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	result := cmd.ExecuteWithAgent(structs.Task{Params: "not json"}, agent)
	if result.Status != "error" {
		t.Error("Expected error for bad JSON")
	}
}

func TestConfigUnknownAction(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "badaction"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "error" {
		t.Error("Expected error for unknown action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("Expected unknown action error, got: %s", result.Output)
	}
}

// --- config set tests ---

func TestConfigSetMissingKey(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "set"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "error" {
		t.Error("Expected error for missing key")
	}
	if !strings.Contains(result.Output, "key is required") {
		t.Errorf("Expected key required error, got: %s", result.Output)
	}
}

func TestConfigSetUnknownKey(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "nonexistent", Value: "x"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "error" {
		t.Error("Expected error for unknown key")
	}
	if !strings.Contains(result.Output, "unknown config key") {
		t.Errorf("Expected unknown key error, got: %s", result.Output)
	}
}

func TestConfigSetSleep(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "sleep", Value: "60"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if agent.SleepInterval != 60 {
		t.Errorf("Expected SleepInterval=60, got %d", agent.SleepInterval)
	}
	if !strings.Contains(result.Output, "30") && !strings.Contains(result.Output, "60") {
		t.Errorf("Expected old→new in output, got: %s", result.Output)
	}
}

func TestConfigSetSleepInvalid(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	tests := []string{"abc", "-5", "12.5"}
	for _, val := range tests {
		params, _ := json.Marshal(ConfigParams{Action: "set", Key: "sleep", Value: val})
		result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
		if result.Status != "error" {
			t.Errorf("Expected error for sleep=%s, got %s", val, result.Status)
		}
	}
}

func TestConfigSetSleepZero(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "sleep", Value: "0"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success for sleep=0, got %s: %s", result.Status, result.Output)
	}
	if agent.SleepInterval != 0 {
		t.Errorf("Expected SleepInterval=0, got %d", agent.SleepInterval)
	}
}

func TestConfigSetJitter(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "jitter", Value: "50"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if agent.Jitter != 50 {
		t.Errorf("Expected Jitter=50, got %d", agent.Jitter)
	}
}

func TestConfigSetJitterBoundary(t *testing.T) {
	cmd := &ConfigCommand{}

	tests := []struct {
		value  string
		expect string // "success" or "error"
	}{
		{"0", "success"},
		{"100", "success"},
		{"101", "error"},
		{"-1", "error"},
		{"abc", "error"},
	}

	for _, tc := range tests {
		t.Run("jitter="+tc.value, func(t *testing.T) {
			agent := newTestAgent()
			params, _ := json.Marshal(ConfigParams{Action: "set", Key: "jitter", Value: tc.value})
			result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
			if result.Status != tc.expect {
				t.Errorf("jitter=%s: expected %s, got %s: %s", tc.value, tc.expect, result.Status, result.Output)
			}
		})
	}
}

func TestConfigSetKillDate(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	// Unix timestamp
	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "killdate", Value: "1735689600"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success for unix timestamp, got %s: %s", result.Status, result.Output)
	}
	if agent.KillDate != 1735689600 {
		t.Errorf("Expected KillDate=1735689600, got %d", agent.KillDate)
	}
}

func TestConfigSetKillDateFormat(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	// Date format
	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "killdate", Value: "2026-12-31"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success for date format, got %s: %s", result.Status, result.Output)
	}
	if agent.KillDate == 0 {
		t.Error("Expected non-zero KillDate")
	}
}

func TestConfigSetKillDateDisable(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()
	agent.KillDate = 1735689600

	for _, val := range []string{"0", "disable", "off"} {
		agent.KillDate = 1735689600
		params, _ := json.Marshal(ConfigParams{Action: "set", Key: "killdate", Value: val})
		result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
		if result.Status != "success" {
			t.Errorf("Expected success for killdate=%s, got %s", val, result.Status)
		}
		if agent.KillDate != 0 {
			t.Errorf("Expected KillDate=0 for value=%s, got %d", val, agent.KillDate)
		}
	}
}

func TestConfigSetKillDateInvalid(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "killdate", Value: "not-a-date"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "error" {
		t.Error("Expected error for invalid date")
	}
}

func TestConfigSetWorkingHours(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	// Set start
	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "working_hours_start", Value: "09:00"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success for wh_start, got %s: %s", result.Status, result.Output)
	}
	if agent.WorkingHoursStart != 540 { // 9 * 60
		t.Errorf("Expected WorkingHoursStart=540, got %d", agent.WorkingHoursStart)
	}

	// Set end
	params, _ = json.Marshal(ConfigParams{Action: "set", Key: "working_hours_end", Value: "17:00"})
	result = cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success for wh_end, got %s: %s", result.Status, result.Output)
	}
	if agent.WorkingHoursEnd != 1020 { // 17 * 60
		t.Errorf("Expected WorkingHoursEnd=1020, got %d", agent.WorkingHoursEnd)
	}
}

func TestConfigSetWorkingHoursAliases(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	// Use short aliases
	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "wh_start", Value: "08:30"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success for wh_start alias, got %s: %s", result.Status, result.Output)
	}

	params, _ = json.Marshal(ConfigParams{Action: "set", Key: "wh_end", Value: "18:00"})
	result = cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success for wh_end alias, got %s: %s", result.Status, result.Output)
	}
}

func TestConfigSetWorkingHoursDisable(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()
	agent.WorkingHoursStart = 540

	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "working_hours_start", Value: "disable"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if agent.WorkingHoursStart != 0 {
		t.Errorf("Expected WorkingHoursStart=0, got %d", agent.WorkingHoursStart)
	}
}

func TestConfigSetWorkingDays(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "working_days", Value: "1,2,3,4,5"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success for working days, got %s: %s", result.Status, result.Output)
	}
	if len(agent.WorkingDays) != 5 {
		t.Errorf("Expected 5 working days, got %d: %v", len(agent.WorkingDays), agent.WorkingDays)
	}
}

func TestConfigSetWorkingDaysDisable(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()
	agent.WorkingDays = []int{1, 2, 3, 4, 5}

	for _, val := range []string{"disable", "all", "off"} {
		agent.WorkingDays = []int{1, 2, 3}
		params, _ := json.Marshal(ConfigParams{Action: "set", Key: "working_days", Value: val})
		result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
		if result.Status != "success" {
			t.Errorf("Expected success for %s, got %s", val, result.Status)
		}
		if agent.WorkingDays != nil {
			t.Errorf("Expected nil working days for %s, got %v", val, agent.WorkingDays)
		}
	}
}

func TestConfigSetWorkingDaysAlias(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "wh_days", Value: "1,5"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success for wh_days alias, got %s: %s", result.Status, result.Output)
	}
}

func TestConfigSetDefaultPPID(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "default_ppid", Value: "4444"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if agent.DefaultPPID != 4444 {
		t.Errorf("Expected DefaultPPID=4444, got %d", agent.DefaultPPID)
	}
}

func TestConfigSetDefaultPPIDAlias(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "ppid", Value: "1234"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success for ppid alias, got %s: %s", result.Status, result.Output)
	}
	if agent.DefaultPPID != 1234 {
		t.Errorf("Expected DefaultPPID=1234, got %d", agent.DefaultPPID)
	}
}

func TestConfigSetDefaultPPIDDisable(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()
	agent.DefaultPPID = 5678

	for _, val := range []string{"0", "disable", "off"} {
		agent.DefaultPPID = 5678
		params, _ := json.Marshal(ConfigParams{Action: "set", Key: "default_ppid", Value: val})
		result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
		if result.Status != "success" {
			t.Errorf("Expected success for %s, got %s", val, result.Status)
		}
		if agent.DefaultPPID != 0 {
			t.Errorf("Expected DefaultPPID=0 for %s, got %d", val, agent.DefaultPPID)
		}
	}
}

func TestConfigSetDefaultPPIDInvalid(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "set", Key: "default_ppid", Value: "abc"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "error" {
		t.Error("Expected error for invalid PPID")
	}
}

func TestConfigShowKillDate(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()
	agent.KillDate = 1735689600

	result := cmd.ExecuteWithAgent(structs.Task{Params: ""}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Kill Date:") {
		t.Errorf("Expected Kill Date in output, got: %s", result.Output)
	}
}

func TestConfigShowWorkingHours(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()
	agent.WorkingHoursStart = 540 // 09:00
	agent.WorkingHoursEnd = 1020  // 17:00

	result := cmd.ExecuteWithAgent(structs.Task{Params: ""}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestConfigShowDefaultPPID(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()
	agent.DefaultPPID = 4444

	result := cmd.ExecuteWithAgent(structs.Task{Params: ""}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "4444") {
		t.Errorf("Expected PPID 4444 in output, got: %s", result.Output)
	}
}

func TestConfigActionCaseInsensitive(t *testing.T) {
	cmd := &ConfigCommand{}
	agent := newTestAgent()

	params, _ := json.Marshal(ConfigParams{Action: "SHOW"})
	result := cmd.ExecuteWithAgent(structs.Task{Params: string(params)}, agent)
	if result.Status != "success" {
		t.Errorf("Expected success for uppercase SHOW, got %s", result.Status)
	}
}
