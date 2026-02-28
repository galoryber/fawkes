package commands

import (
	"testing"
)

func TestErrorResult(t *testing.T) {
	r := errorResult("something went wrong")
	if r.Output != "something went wrong" {
		t.Errorf("expected 'something went wrong', got %q", r.Output)
	}
	if r.Status != "error" {
		t.Errorf("expected 'error' status, got %q", r.Status)
	}
	if !r.Completed {
		t.Error("expected Completed=true")
	}
}

func TestErrorf(t *testing.T) {
	r := errorf("failed to open %s: %v", "file.txt", "permission denied")
	expected := "failed to open file.txt: permission denied"
	if r.Output != expected {
		t.Errorf("expected %q, got %q", expected, r.Output)
	}
	if r.Status != "error" {
		t.Errorf("expected 'error' status, got %q", r.Status)
	}
	if !r.Completed {
		t.Error("expected Completed=true")
	}
}

func TestSuccessResult(t *testing.T) {
	r := successResult("operation complete")
	if r.Output != "operation complete" {
		t.Errorf("expected 'operation complete', got %q", r.Output)
	}
	if r.Status != "completed" {
		t.Errorf("expected 'completed' status, got %q", r.Status)
	}
	if !r.Completed {
		t.Error("expected Completed=true")
	}
}

func TestSuccessf(t *testing.T) {
	r := successf("deleted %d files", 5)
	if r.Output != "deleted 5 files" {
		t.Errorf("expected 'deleted 5 files', got %q", r.Output)
	}
	if r.Status != "completed" {
		t.Errorf("expected 'completed' status, got %q", r.Status)
	}
}

func TestParseArgs_EmptyParams(t *testing.T) {
	var target struct{ Name string }
	result, ok := parseArgs("", &target)
	if ok {
		t.Error("expected ok=false for empty params")
	}
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
}

func TestParseArgs_InvalidJSON(t *testing.T) {
	var target struct{ Name string }
	result, ok := parseArgs("not json", &target)
	if ok {
		t.Error("expected ok=false for invalid JSON")
	}
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
}

func TestParseArgs_ValidJSON(t *testing.T) {
	var target struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	result, ok := parseArgs(`{"name":"test","age":42}`, &target)
	if !ok {
		t.Errorf("expected ok=true, got error: %s", result.Output)
	}
	if target.Name != "test" {
		t.Errorf("expected name=test, got %q", target.Name)
	}
	if target.Age != 42 {
		t.Errorf("expected age=42, got %d", target.Age)
	}
}

func TestParseArgs_PartialJSON(t *testing.T) {
	var target struct {
		Required string `json:"required"`
		Optional string `json:"optional"`
	}
	result, ok := parseArgs(`{"required":"yes"}`, &target)
	if !ok {
		t.Errorf("expected ok=true, got error: %s", result.Output)
	}
	if target.Required != "yes" {
		t.Errorf("expected required=yes, got %q", target.Required)
	}
	if target.Optional != "" {
		t.Errorf("expected empty optional, got %q", target.Optional)
	}
}
