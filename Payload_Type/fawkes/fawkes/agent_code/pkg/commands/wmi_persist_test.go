package commands

import (
	"testing"

	"fawkes/pkg/structs"
)

func TestWmiPersistName(t *testing.T) {
	cmd := &WmiPersistCommand{}
	if cmd.Name() != "wmi-persist" {
		t.Errorf("expected wmi-persist, got %s", cmd.Name())
	}
}

func TestWmiPersistEmptyParams(t *testing.T) {
	cmd := &WmiPersistCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("empty params should return error")
	}
}

func TestWmiPersistBadJSON(t *testing.T) {
	cmd := &WmiPersistCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("bad JSON should return error")
	}
}

func TestWmiPersistInvalidAction(t *testing.T) {
	cmd := &WmiPersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"badaction"}`})
	if result.Status != "error" {
		t.Error("invalid action should return error")
	}
}

func TestWmiPersistInstallMissingName(t *testing.T) {
	cmd := &WmiPersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"install","command":"calc.exe"}`})
	if result.Status != "error" {
		t.Error("install without name should return error")
	}
}

func TestWmiPersistInstallMissingCommand(t *testing.T) {
	cmd := &WmiPersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"install","name":"test"}`})
	if result.Status != "error" {
		t.Error("install without command should return error")
	}
}

func TestWmiPersistRemoveMissingName(t *testing.T) {
	cmd := &WmiPersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"remove"}`})
	if result.Status != "error" {
		t.Error("remove without name should return error")
	}
}

func TestBuildWQLTriggerLogon(t *testing.T) {
	wql, err := buildWQLTrigger("logon", 0, "")
	if err != nil {
		t.Fatalf("logon trigger should not error: %v", err)
	}
	if !contains(wql, "Win32_LogonSession") {
		t.Error("logon trigger should reference Win32_LogonSession")
	}
}

func TestBuildWQLTriggerStartup(t *testing.T) {
	wql, err := buildWQLTrigger("startup", 0, "")
	if err != nil {
		t.Fatalf("startup trigger should not error: %v", err)
	}
	if !contains(wql, "SystemUpTime") {
		t.Error("startup trigger should reference SystemUpTime")
	}
}

func TestBuildWQLTriggerInterval(t *testing.T) {
	wql, err := buildWQLTrigger("interval", 60, "")
	if err != nil {
		t.Fatalf("interval trigger should not error: %v", err)
	}
	if !contains(wql, "__TimerEvent") {
		t.Error("interval trigger should reference __TimerEvent")
	}
}

func TestBuildWQLTriggerProcess(t *testing.T) {
	wql, err := buildWQLTrigger("process", 0, "notepad.exe")
	if err != nil {
		t.Fatalf("process trigger should not error: %v", err)
	}
	if !contains(wql, "notepad.exe") {
		t.Error("process trigger should contain process name")
	}
	if !contains(wql, "Win32_Process") {
		t.Error("process trigger should reference Win32_Process")
	}
}

func TestBuildWQLTriggerProcessMissingName(t *testing.T) {
	_, err := buildWQLTrigger("process", 0, "")
	if err == nil {
		t.Error("process trigger without name should error")
	}
}

func TestBuildWQLTriggerUnknown(t *testing.T) {
	_, err := buildWQLTrigger("badtrigger", 0, "")
	if err == nil {
		t.Error("unknown trigger should error")
	}
}
