package commands

import (
	"testing"

	"fawkes/pkg/structs"
)

type testArgs struct {
	Name   string `json:"name"`
	Count  int    `json:"count"`
	Active bool   `json:"active"`
}

func TestUnmarshalParams_ValidJSON(t *testing.T) {
	task := structs.Task{Params: `{"name":"test","count":5,"active":true}`}
	args, errResult := unmarshalParams[testArgs](task)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Output)
	}
	if args.Name != "test" {
		t.Errorf("name: got %q, want %q", args.Name, "test")
	}
	if args.Count != 5 {
		t.Errorf("count: got %d, want 5", args.Count)
	}
	if !args.Active {
		t.Error("active: got false, want true")
	}
}

func TestUnmarshalParams_EmptyParams(t *testing.T) {
	task := structs.Task{Params: ""}
	args, errResult := unmarshalParams[testArgs](task)
	if errResult != nil {
		t.Fatalf("unexpected error for empty params: %s", errResult.Output)
	}
	// Zero values expected
	if args.Name != "" || args.Count != 0 || args.Active {
		t.Error("empty params should return zero values")
	}
}

func TestUnmarshalParams_InvalidJSON(t *testing.T) {
	task := structs.Task{Params: "not valid json"}
	_, errResult := unmarshalParams[testArgs](task)
	if errResult == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if errResult.Status != "error" {
		t.Errorf("status: got %q, want %q", errResult.Status, "error")
	}
}

func TestUnmarshalParams_PartialJSON(t *testing.T) {
	// Only some fields — others get zero values
	task := structs.Task{Params: `{"name":"partial"}`}
	args, errResult := unmarshalParams[testArgs](task)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Output)
	}
	if args.Name != "partial" {
		t.Errorf("name: got %q, want %q", args.Name, "partial")
	}
	if args.Count != 0 {
		t.Errorf("count: got %d, want 0", args.Count)
	}
}

func TestRequireParams_ValidJSON(t *testing.T) {
	task := structs.Task{Params: `{"name":"required"}`}
	args, errResult := requireParams[testArgs](task)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Output)
	}
	if args.Name != "required" {
		t.Errorf("name: got %q, want %q", args.Name, "required")
	}
}

func TestRequireParams_EmptyParams(t *testing.T) {
	task := structs.Task{Params: ""}
	_, errResult := requireParams[testArgs](task)
	if errResult == nil {
		t.Fatal("expected error for empty params with requireParams")
	}
	if errResult.Status != "error" {
		t.Errorf("status: got %q, want %q", errResult.Status, "error")
	}
}

func TestRequireParams_InvalidJSON(t *testing.T) {
	task := structs.Task{Params: "{invalid"}
	_, errResult := requireParams[testArgs](task)
	if errResult == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestUnmarshalParams_TypeMismatch(t *testing.T) {
	// String where int expected — JSON will fail to unmarshal
	task := structs.Task{Params: `{"count":"not a number"}`}
	_, errResult := unmarshalParams[testArgs](task)
	if errResult == nil {
		t.Fatal("expected error for type mismatch")
	}
}
