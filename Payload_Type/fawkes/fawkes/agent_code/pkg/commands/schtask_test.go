//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSchtaskCommand_Name(t *testing.T) {
	cmd := &SchtaskCommand{}
	if cmd.Name() != "schtask" {
		t.Errorf("expected 'schtask', got '%s'", cmd.Name())
	}
}

func TestSchtaskCommand_Description(t *testing.T) {
	cmd := &SchtaskCommand{}
	if !strings.Contains(cmd.Description(), "COM API") {
		t.Errorf("description should mention COM API, got '%s'", cmd.Description())
	}
}

func TestSchtaskCommand_EmptyParams(t *testing.T) {
	cmd := &SchtaskCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("expected error for empty params")
	}
}

func TestSchtaskCommand_InvalidJSON(t *testing.T) {
	cmd := &SchtaskCommand{}
	result := cmd.Execute(structs.Task{Params: "{bad"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
}

func TestSchtaskCommand_UnknownAction(t *testing.T) {
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

func TestSchtaskCommand_CreateNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "create"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("expected name required message, got '%s'", result.Output)
	}
}

func TestSchtaskCommand_CreateNoProgram(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "create", Name: "TestTask"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when program is empty")
	}
	if !strings.Contains(result.Output, "program is required") {
		t.Errorf("expected program required message, got '%s'", result.Output)
	}
}

func TestSchtaskCommand_QueryNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "query"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty")
	}
}

func TestSchtaskCommand_DeleteNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "delete"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty")
	}
}

func TestSchtaskCommand_RunNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "run"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty")
	}
}

func TestSchtaskCommand_List(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "list"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for list, got '%s': %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Scheduled Tasks") {
		t.Errorf("expected scheduled tasks header, got '%s'", result.Output)
	}
}

// TestTriggerTypeFromString moved to command_helpers_test.go

func TestTaskStateIntToString(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "Unknown"},
		{1, "Disabled"},
		{2, "Queued"},
		{3, "Ready"},
		{4, "Running"},
		{99, "Unknown(99)"},
	}

	for _, tt := range tests {
		result := taskStateIntToString(tt.input)
		if result != tt.expected {
			t.Errorf("taskStateIntToString(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestTaskStateToString_Types(t *testing.T) {
	// Test int32
	result := taskStateToString(int32(3))
	if result != "Ready" {
		t.Errorf("taskStateToString(int32(3)) = %q, want 'Ready'", result)
	}

	// Test int64
	result = taskStateToString(int64(4))
	if result != "Running" {
		t.Errorf("taskStateToString(int64(4)) = %q, want 'Running'", result)
	}

	// Test int
	result = taskStateToString(1)
	if result != "Disabled" {
		t.Errorf("taskStateToString(1) = %q, want 'Disabled'", result)
	}

	// Test string fallback
	result = taskStateToString("some string")
	if result != "some string" {
		t.Errorf("taskStateToString(\"some string\") = %q, want 'some string'", result)
	}
}

func TestSchtaskCommand_EnableNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "enable"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("expected name required message, got '%s'", result.Output)
	}
}

func TestSchtaskCommand_DisableNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "disable"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("expected name required message, got '%s'", result.Output)
	}
}

func TestSchtaskCommand_StopNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "stop"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("expected name required message, got '%s'", result.Output)
	}
}

func TestBuildTaskXML_DefaultTrigger(t *testing.T) {
	xml := buildTaskXML(schtaskArgs{Program: "cmd.exe"})
	if !strings.Contains(xml, "<LogonTrigger>") {
		t.Error("expected ONLOGON trigger as default")
	}
	if !strings.Contains(xml, "<Command>cmd.exe</Command>") {
		t.Error("expected Command element with program")
	}
	if strings.Contains(xml, "<Arguments>") {
		t.Error("should not include Arguments when args is empty")
	}
}

func TestBuildTaskXML_WithArgs(t *testing.T) {
	xml := buildTaskXML(schtaskArgs{Program: "cmd.exe", Args: "/c echo test"})
	if !strings.Contains(xml, "<Arguments>/c echo test</Arguments>") {
		t.Errorf("expected Args element, got:\n%s", xml)
	}
}

func TestBuildTaskXML_SystemUser(t *testing.T) {
	xml := buildTaskXML(schtaskArgs{
		Program: "cmd.exe",
		User:    "SYSTEM",
	})
	if !strings.Contains(xml, "S-1-5-18") {
		t.Error("SYSTEM user should use SID S-1-5-18")
	}
	if !strings.Contains(xml, "HighestAvailable") {
		t.Error("SYSTEM user should have HighestAvailable RunLevel")
	}
}

func TestBuildTaskXML_NTAuthoritySystem(t *testing.T) {
	xml := buildTaskXML(schtaskArgs{
		Program: "cmd.exe",
		User:    "NT AUTHORITY\\SYSTEM",
	})
	if !strings.Contains(xml, "S-1-5-18") {
		t.Error("NT AUTHORITY\\SYSTEM should use SID S-1-5-18")
	}
}

func TestBuildTaskXML_RegularUser(t *testing.T) {
	xml := buildTaskXML(schtaskArgs{
		Program: "cmd.exe",
		User:    "DOMAIN\\user",
	})
	if !strings.Contains(xml, "DOMAIN\\user") {
		t.Error("expected user in UserId element")
	}
	if !strings.Contains(xml, "InteractiveToken") {
		t.Error("regular user should have InteractiveToken LogonType")
	}
	if !strings.Contains(xml, "LeastPrivilege") {
		t.Error("regular user should have LeastPrivilege RunLevel")
	}
}

func TestBuildTaskXML_XMLEscaping(t *testing.T) {
	xml := buildTaskXML(schtaskArgs{
		Program: "cmd.exe",
		Args:    "/c echo <test>&\"done\"",
	})
	if strings.Contains(xml, "<test>") {
		t.Error("XML special chars should be escaped")
	}
	if !strings.Contains(xml, "&lt;test&gt;") {
		t.Error("expected escaped angle brackets")
	}
	if !strings.Contains(xml, "&amp;") {
		t.Error("expected escaped ampersand")
	}
}

func TestBuildTaskXML_TriggerTypes(t *testing.T) {
	tests := []struct {
		trigger  string
		contains string
	}{
		{"ONLOGON", "<LogonTrigger>"},
		{"ONSTART", "<BootTrigger>"},
		{"ONIDLE", "<IdleTrigger>"},
		{"DAILY", "<CalendarTrigger>"},
		{"WEEKLY", "<ScheduleByWeek>"},
		{"ONCE", "<TimeTrigger>"},
	}
	for _, tt := range tests {
		xml := buildTaskXML(schtaskArgs{Program: "cmd.exe", Trigger: tt.trigger})
		if !strings.Contains(xml, tt.contains) {
			t.Errorf("trigger %s: expected %s in output", tt.trigger, tt.contains)
		}
	}
}

func TestBuildTaskXML_XMLHeader(t *testing.T) {
	xml := buildTaskXML(schtaskArgs{Program: "cmd.exe"})
	if !strings.HasPrefix(xml, `<?xml version="1.0"`) {
		t.Error("expected XML declaration")
	}
	if !strings.Contains(xml, "schemas.microsoft.com/windows/2004/02/mit/task") {
		t.Error("expected Task Scheduler namespace")
	}
}

func TestExtractXMLValue_Basic(t *testing.T) {
	xml := "<Root><Name>test-task</Name><Status>Ready</Status></Root>"
	if v := extractXMLValue(xml, "Name"); v != "test-task" {
		t.Errorf("expected 'test-task', got %q", v)
	}
	if v := extractXMLValue(xml, "Status"); v != "Ready" {
		t.Errorf("expected 'Ready', got %q", v)
	}
}

func TestExtractXMLValue_NotFound(t *testing.T) {
	xml := "<Root><Name>test</Name></Root>"
	if v := extractXMLValue(xml, "Missing"); v != "" {
		t.Errorf("expected empty for missing tag, got %q", v)
	}
}

func TestExtractXMLValue_Empty(t *testing.T) {
	xml := "<Root><Name></Name></Root>"
	if v := extractXMLValue(xml, "Name"); v != "" {
		t.Errorf("expected empty string, got %q", v)
	}
}

func TestExtractXMLValue_Whitespace(t *testing.T) {
	xml := "<Root><Name>  padded  </Name></Root>"
	if v := extractXMLValue(xml, "Name"); v != "padded" {
		t.Errorf("expected trimmed 'padded', got %q", v)
	}
}

func TestExtractXMLValue_UnclosedTag(t *testing.T) {
	xml := "<Root><Name>value"
	if v := extractXMLValue(xml, "Name"); v != "" {
		t.Errorf("expected empty for unclosed tag, got %q", v)
	}
}

func TestExtractXMLValue_Nested(t *testing.T) {
	xml := "<Task><Settings><Enabled>true</Enabled></Settings></Task>"
	if v := extractXMLValue(xml, "Enabled"); v != "true" {
		t.Errorf("expected 'true', got %q", v)
	}
}

// Integration test: create → query → disable → enable → run → stop → delete lifecycle
func TestSchtaskCommand_Lifecycle(t *testing.T) {
	cmd := &SchtaskCommand{}
	taskName := "FawkesUnitTest_schtask"

	// Create
	createParams, _ := json.Marshal(schtaskArgs{
		Action:  "create",
		Name:    taskName,
		Program: "cmd.exe",
		Args:    "/c echo test",
		Trigger: "ONCE",
	})
	result := cmd.Execute(structs.Task{Params: string(createParams)})
	if result.Status != "success" {
		t.Fatalf("create failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Created scheduled task") {
		t.Errorf("expected creation message, got '%s'", result.Output)
	}

	// Query
	queryParams, _ := json.Marshal(schtaskArgs{
		Action: "query",
		Name:   taskName,
	})
	result = cmd.Execute(structs.Task{Params: string(queryParams)})
	if result.Status != "success" {
		t.Fatalf("query failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, taskName) {
		t.Errorf("expected task name in output, got '%s'", result.Output)
	}

	// Disable
	disableParams, _ := json.Marshal(schtaskArgs{
		Action: "disable",
		Name:   taskName,
	})
	result = cmd.Execute(structs.Task{Params: string(disableParams)})
	if result.Status != "success" {
		t.Fatalf("disable failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Disabled") {
		t.Errorf("expected disabled message, got '%s'", result.Output)
	}

	// Enable
	enableParams, _ := json.Marshal(schtaskArgs{
		Action: "enable",
		Name:   taskName,
	})
	result = cmd.Execute(structs.Task{Params: string(enableParams)})
	if result.Status != "success" {
		t.Fatalf("enable failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Enabled") {
		t.Errorf("expected enabled message, got '%s'", result.Output)
	}

	// Delete (cleanup)
	deleteParams, _ := json.Marshal(schtaskArgs{
		Action: "delete",
		Name:   taskName,
	})
	result = cmd.Execute(structs.Task{Params: string(deleteParams)})
	if result.Status != "success" {
		t.Fatalf("delete failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Deleted") {
		t.Errorf("expected deletion message, got '%s'", result.Output)
	}
}
