package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestRouteName(t *testing.T) {
	cmd := &RouteCommand{}
	if cmd.Name() != "route" {
		t.Errorf("expected 'route', got '%s'", cmd.Name())
	}
}

func TestRouteDescription(t *testing.T) {
	cmd := &RouteCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestRouteExecute(t *testing.T) {
	cmd := &RouteCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if !result.Completed {
		t.Error("expected completed=true")
	}
	// On a real system, we should get routes
	if result.Status == "success" {
		if !strings.Contains(result.Output, "Routing Table") {
			t.Error("output should contain 'Routing Table' header")
		}
		if !strings.Contains(result.Output, "Destination") {
			t.Error("output should contain column headers")
		}
	}
}

func TestRouteEntryStruct(t *testing.T) {
	r := RouteEntry{
		Destination: "192.168.1.0",
		Gateway:     "192.168.1.1",
		Netmask:     "255.255.255.0",
		Interface:   "eth0",
		Metric:      100,
		Flags:       "UG",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var r2 RouteEntry
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if r2.Destination != "192.168.1.0" || r2.Gateway != "192.168.1.1" {
		t.Error("round-trip failed")
	}
	if r2.Metric != 100 {
		t.Errorf("expected metric 100, got %d", r2.Metric)
	}
}

func TestRouteFormatOutput(t *testing.T) {
	cmd := &RouteCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status == "success" {
		// Check for proper formatting
		lines := strings.Split(result.Output, "\n")
		if len(lines) < 3 {
			t.Error("expected at least 3 lines (header, separator, routes)")
		}
	}
}
