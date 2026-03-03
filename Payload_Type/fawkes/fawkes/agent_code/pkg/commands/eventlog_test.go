//go:build windows

package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestEventLogCommand_NameAndDescription(t *testing.T) {
	cmd := &EventLogCommand{}
	if cmd.Name() != "eventlog" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "eventlog")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if !strings.Contains(cmd.Description(), "Event Log") {
		t.Error("Description should mention Event Log")
	}
}

func TestEventLogCommand_InvalidJSON(t *testing.T) {
	cmd := &EventLogCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestEventLogCommand_UnknownAction(t *testing.T) {
	cmd := &EventLogCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"badaction"}`})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected 'Unknown action' in output, got: %s", result.Output)
	}
}

func TestEventLogCommand_DefaultAction(t *testing.T) {
	cmd := &EventLogCommand{}
	// Empty params should default to "list" action
	result := cmd.Execute(structs.Task{Params: ""})
	// Should succeed with channel list (or error if no perms, but not "unknown action")
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("Empty params should default to list action")
	}
}

func TestEventLogCommand_QueryNoChannel(t *testing.T) {
	cmd := &EventLogCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"query"}`})
	if result.Status != "error" {
		t.Errorf("expected error when query without channel, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Channel is required") {
		t.Errorf("expected channel required message, got: %s", result.Output)
	}
}

func TestEventLogCommand_ClearNoChannel(t *testing.T) {
	cmd := &EventLogCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"clear"}`})
	if result.Status != "error" {
		t.Errorf("expected error when clear without channel, got %q", result.Status)
	}
}

func TestEventLogCommand_InfoNoChannel(t *testing.T) {
	cmd := &EventLogCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"info"}`})
	if result.Status != "error" {
		t.Errorf("expected error when info without channel, got %q", result.Status)
	}
}

func TestBuildEventXPath_NoFilter(t *testing.T) {
	xpath := buildEventXPath("", 0)
	if xpath != "*" {
		t.Errorf("expected '*', got %q", xpath)
	}
}

func TestBuildEventXPath_EventID(t *testing.T) {
	xpath := buildEventXPath("", 4624)
	if !strings.Contains(xpath, "EventID=4624") {
		t.Errorf("expected EventID=4624, got %q", xpath)
	}
}

func TestBuildEventXPath_TimeFilter(t *testing.T) {
	xpath := buildEventXPath("24h", 0)
	if !strings.Contains(xpath, "timediff") {
		t.Errorf("expected timediff in xpath, got %q", xpath)
	}
	if !strings.Contains(xpath, "86400000") {
		t.Errorf("expected 86400000 ms (24h), got %q", xpath)
	}
}

func TestBuildEventXPath_Combined(t *testing.T) {
	xpath := buildEventXPath("1h", 4625)
	if !strings.Contains(xpath, "EventID=4625") {
		t.Errorf("expected EventID=4625, got %q", xpath)
	}
	if !strings.Contains(xpath, "timediff") {
		t.Errorf("expected timediff, got %q", xpath)
	}
}

func TestBuildEventXPath_RawXPath(t *testing.T) {
	raw := "*[System[EventID=1234]]"
	xpath := buildEventXPath(raw, 0)
	if xpath != raw {
		t.Errorf("raw XPath should pass through, got %q", xpath)
	}
}

func TestExtractXMLField_EventLog(t *testing.T) {
	xml := `<Event><System><EventID>4624</EventID><Level>4</Level></System></Event>`
	if v := extractXMLField(xml, "EventID"); v != "4624" {
		t.Errorf("EventID: got %q, want %q", v, "4624")
	}
	if v := extractXMLField(xml, "Level"); v != "4" {
		t.Errorf("Level: got %q, want %q", v, "4")
	}
	if v := extractXMLField(xml, "Missing"); v != "" {
		t.Errorf("Missing field should return empty, got %q", v)
	}
}

func TestExtractXMLField_WithAttributes(t *testing.T) {
	xml := `<Event><System><EventID Qualifiers='0'>1102</EventID></System></Event>`
	if v := extractXMLField(xml, "EventID"); v != "1102" {
		t.Errorf("EventID with attributes: got %q, want %q", v, "1102")
	}
}

// TestExtractXMLAttr, TestSummarizeEventXML, TestFormatEvtLogSize moved to
// command_helpers_test.go. TestDaysToDate moved to eventlog_helpers_test.go.
