package commands

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

func TestLapsName(t *testing.T) {
	cmd := &LapsCommand{}
	if cmd.Name() != "laps" {
		t.Errorf("expected 'laps', got '%s'", cmd.Name())
	}
}

func TestLapsDescription(t *testing.T) {
	cmd := &LapsCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestLapsEmptyParams(t *testing.T) {
	cmd := &LapsCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("expected error for empty params")
	}
}

func TestLapsInvalidJSON(t *testing.T) {
	cmd := &LapsCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
}

func TestLapsMissingServer(t *testing.T) {
	cmd := &LapsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"username":"test","password":"test"}`})
	if result.Status != "error" {
		t.Error("expected error for missing server")
	}
	if !strings.Contains(result.Output, "server parameter required") {
		t.Errorf("expected server required message, got: %s", result.Output)
	}
}

func TestFiletimeToTime(t *testing.T) {
	// January 1, 2025 00:00:00 UTC as Windows FILETIME
	// Unix timestamp: 1735689600
	// FILETIME = (1735689600 + 11644473600) * 10000000 = 133801632000000000
	ft := int64(133801632000000000)
	result := filetimeToTime(ft)
	expected := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if !result.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestFiletimeToTimeEpoch(t *testing.T) {
	// Unix epoch: January 1, 1970 00:00:00 UTC
	// FILETIME = 11644473600 * 10000000 = 116444736000000000
	ft := int64(116444736000000000)
	result := filetimeToTime(ft)
	expected := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	if !result.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestLapsExpiryStatus(t *testing.T) {
	// Test expired
	past := time.Now().Add(-24 * time.Hour)
	status := lapsExpiryStatus(past)
	if status != "EXPIRED" {
		t.Errorf("expected EXPIRED, got %s", status)
	}

	// Test future
	future := time.Now().Add(48 * time.Hour)
	status = lapsExpiryStatus(future)
	if !strings.Contains(status, "expires in") {
		t.Errorf("expected 'expires in', got %s", status)
	}
	if !strings.Contains(status, "d") || !strings.Contains(status, "h") {
		t.Errorf("expected days and hours format, got %s", status)
	}
}

func TestLapsV2PasswordParsing(t *testing.T) {
	// Test JSON parsing of LAPS v2 password structure
	jsonStr := `{"n":"DC01$","t":"2025-01-15T12:00:00.0000000Z","p":"SuperSecret123!","a":"Administrator"}`
	var v2 lapsV2Password
	if err := parseJSON([]byte(jsonStr), &v2); err != nil {
		t.Fatalf("failed to parse LAPS v2 JSON: %v", err)
	}
	if v2.AccountName != "DC01$" {
		t.Errorf("expected AccountName 'DC01$', got '%s'", v2.AccountName)
	}
	if v2.Password != "SuperSecret123!" {
		t.Errorf("expected Password 'SuperSecret123!', got '%s'", v2.Password)
	}
	if v2.ManagedName != "Administrator" {
		t.Errorf("expected ManagedName 'Administrator', got '%s'", v2.ManagedName)
	}
}

// parseJSON is a helper for tests to avoid importing encoding/json
func parseJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
