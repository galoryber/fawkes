//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestPrefetchCommandName(t *testing.T) {
	assertCommandName(t, &PrefetchCommand{}, "prefetch")
}

func TestPrefetchCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &PrefetchCommand{})
}

func TestPrefetchEmptyParams(t *testing.T) {
	cmd := &PrefetchCommand{}
	result := cmd.Execute(mockTask("prefetch", ""))
	assertError(t, result)
}

func TestPrefetchInvalidJSON(t *testing.T) {
	cmd := &PrefetchCommand{}
	result := cmd.Execute(mockTask("prefetch", "not json"))
	assertError(t, result)
}

func TestPrefetchUnknownAction(t *testing.T) {
	cmd := &PrefetchCommand{}
	params, _ := json.Marshal(prefetchParams{Action: "badaction"})
	result := cmd.Execute(mockTask("prefetch", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "Unknown action")
}

func TestPrefetchDefaultAction(t *testing.T) {
	cmd := &PrefetchCommand{}
	// Action="" should default to "list"
	params, _ := json.Marshal(prefetchParams{})
	result := cmd.Execute(mockTask("prefetch", string(params)))
	// Will try to read Prefetch dir — may succeed or error
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status: %q", result.Status)
	}
}

func TestPrefetchParamsUnmarshal(t *testing.T) {
	var params prefetchParams
	data := `{"action":"parse","name":"CALC.EXE","count":10}`
	if err := json.Unmarshal([]byte(data), &params); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if params.Action != "parse" {
		t.Errorf("expected action=parse, got %q", params.Action)
	}
	if params.Name != "CALC.EXE" {
		t.Errorf("expected name=CALC.EXE, got %q", params.Name)
	}
	if params.Count != 10 {
		t.Errorf("expected count=10, got %d", params.Count)
	}
}

func TestPrefetchOutputEntryJSON(t *testing.T) {
	entry := prefetchOutputEntry{
		Executable: "CALC.EXE",
		RunCount:   5,
		LastRun:    "2026-01-15 10:30:00",
		FileSize:   32768,
		Hash:       "ABCDEF01",
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded prefetchOutputEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded.Executable != "CALC.EXE" {
		t.Errorf("expected CALC.EXE, got %q", decoded.Executable)
	}
	if decoded.RunCount != 5 {
		t.Errorf("expected 5, got %d", decoded.RunCount)
	}
}
