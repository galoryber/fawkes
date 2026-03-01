package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSleepCommandName(t *testing.T) {
	cmd := &SleepCommand{}
	if cmd.Name() != "sleep" {
		t.Errorf("expected 'sleep', got %q", cmd.Name())
	}
}

func TestSleepExecuteWithoutAgent(t *testing.T) {
	cmd := &SleepCommand{}
	task := structs.NewTask("t", "sleep", "")
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error without agent, got %q", result.Status)
	}
}

func TestSleepWithAgentJSON(t *testing.T) {
	cmd := &SleepCommand{}
	task := structs.NewTask("t", "sleep", "")
	task.Params = `{"interval":30,"jitter":20}`

	agent := &structs.Agent{}
	agent.SleepInterval = 10
	agent.Jitter = 0

	result := cmd.ExecuteWithAgent(task, agent)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if agent.SleepInterval != 30 {
		t.Errorf("expected interval 30, got %d", agent.SleepInterval)
	}
	if agent.Jitter != 20 {
		t.Errorf("expected jitter 20, got %d", agent.Jitter)
	}
}

func TestSleepWithAgentSpaceSeparated(t *testing.T) {
	cmd := &SleepCommand{}
	task := structs.NewTask("t", "sleep", "")
	task.Params = "60 50"

	agent := &structs.Agent{}
	result := cmd.ExecuteWithAgent(task, agent)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if agent.SleepInterval != 60 {
		t.Errorf("expected interval 60, got %d", agent.SleepInterval)
	}
	if agent.Jitter != 50 {
		t.Errorf("expected jitter 50, got %d", agent.Jitter)
	}
}

func TestSleepNegativeInterval(t *testing.T) {
	cmd := &SleepCommand{}
	task := structs.NewTask("t", "sleep", "")
	task.Params = `{"interval":-5,"jitter":0}`

	agent := &structs.Agent{}
	result := cmd.ExecuteWithAgent(task, agent)
	if result.Status != "error" {
		t.Errorf("expected error for negative interval, got %q", result.Status)
	}
}

func TestSleepJitterOutOfRange(t *testing.T) {
	cmd := &SleepCommand{}
	task := structs.NewTask("t", "sleep", "")
	task.Params = `{"interval":10,"jitter":150}`

	agent := &structs.Agent{}
	result := cmd.ExecuteWithAgent(task, agent)
	if result.Status != "error" {
		t.Errorf("expected error for jitter > 100, got %q", result.Status)
	}
}

func TestSleepInvalidIntervalString(t *testing.T) {
	cmd := &SleepCommand{}
	task := structs.NewTask("t", "sleep", "")
	task.Params = "abc"

	agent := &structs.Agent{}
	result := cmd.ExecuteWithAgent(task, agent)
	if result.Status != "error" {
		t.Errorf("expected error for invalid interval string, got %q", result.Status)
	}
}

func TestSleepWorkingHours(t *testing.T) {
	cmd := &SleepCommand{}
	task := structs.NewTask("t", "sleep", "")
	task.Params = `{"interval":10,"jitter":0,"working_start":"09:00","working_end":"17:00","working_days":"1,2,3,4,5"}`

	agent := &structs.Agent{}
	result := cmd.ExecuteWithAgent(task, agent)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "09:00") {
		t.Error("output should mention working hours")
	}
}

func TestSleepDisableWorkingHours(t *testing.T) {
	cmd := &SleepCommand{}
	task := structs.NewTask("t", "sleep", "")
	task.Params = `{"interval":10,"jitter":0,"working_start":"00:00","working_end":"00:00"}`

	agent := &structs.Agent{}
	agent.WorkingHoursStart = 540
	agent.WorkingHoursEnd = 1020

	result := cmd.ExecuteWithAgent(task, agent)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "DISABLED") {
		t.Error("output should mention DISABLED working hours")
	}
}
