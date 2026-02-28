package commands

import (
	"encoding/json"
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
	// On a real system, we should get routes as JSON
	if result.Status == "success" {
		var routes []RouteEntry
		if err := json.Unmarshal([]byte(result.Output), &routes); err != nil {
			t.Errorf("output should be valid JSON array: %v", err)
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

func TestRouteJSONOutput(t *testing.T) {
	cmd := &RouteCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status == "success" && result.Output != "[]" {
		var routes []RouteEntry
		if err := json.Unmarshal([]byte(result.Output), &routes); err != nil {
			t.Errorf("output should be valid JSON: %v", err)
		}
		if len(routes) == 0 {
			t.Error("expected at least one route entry")
		}
	}
}
