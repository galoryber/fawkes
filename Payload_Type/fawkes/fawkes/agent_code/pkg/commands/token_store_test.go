//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestTokenStore_Name(t *testing.T) {
	cmd := &TokenStoreCommand{}
	if got := cmd.Name(); got != "token-store" {
		t.Errorf("Name() = %q, want %q", got, "token-store")
	}
}

func TestTokenStore_Description(t *testing.T) {
	cmd := &TokenStoreCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestTokenStore_InvalidJSON(t *testing.T) {
	cmd := &TokenStoreCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestTokenStore_DefaultActionIsList(t *testing.T) {
	// Empty params should default to list action (which succeeds with empty store)
	cmd := &TokenStoreCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	// list with empty store should succeed
	if result.Status != "success" {
		t.Errorf("Default list action should succeed, got status=%q output=%q", result.Status, result.Output)
	}
}

func TestTokenStore_UnknownAction(t *testing.T) {
	cmd := &TokenStoreCommand{}
	params, _ := json.Marshal(tokenStoreArgs{Action: "invalid"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Unknown action should error, got status=%q", result.Status)
	}
}

func TestTokenStore_SaveRequiresName(t *testing.T) {
	cmd := &TokenStoreCommand{}
	params, _ := json.Marshal(tokenStoreArgs{Action: "save", Name: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Save without name should error, got status=%q", result.Status)
	}
}

func TestTokenStore_UseRequiresName(t *testing.T) {
	cmd := &TokenStoreCommand{}
	params, _ := json.Marshal(tokenStoreArgs{Action: "use", Name: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Use without name should error, got status=%q", result.Status)
	}
}

func TestTokenStore_RemoveRequiresName(t *testing.T) {
	cmd := &TokenStoreCommand{}
	params, _ := json.Marshal(tokenStoreArgs{Action: "remove", Name: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Remove without name should error, got status=%q", result.Status)
	}
}

func TestTokenStore_RemoveNonExistentToken(t *testing.T) {
	cmd := &TokenStoreCommand{}
	params, _ := json.Marshal(tokenStoreArgs{Action: "remove", Name: "nonexistent"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Removing nonexistent token should error, got status=%q", result.Status)
	}
}

func TestTokenStore_UseNonExistentToken(t *testing.T) {
	cmd := &TokenStoreCommand{}
	params, _ := json.Marshal(tokenStoreArgs{Action: "use", Name: "nonexistent"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Using nonexistent token should error, got status=%q", result.Status)
	}
}

func TestTokenStore_ParamParsing(t *testing.T) {
	tests := []struct {
		input  string
		action string
		name   string
	}{
		{`{"action":"save","name":"admin"}`, "save", "admin"},
		{`{"action":"list"}`, "list", ""},
		{`{"action":"use","name":"backup"}`, "use", "backup"},
		{`{"action":"remove","name":"old"}`, "remove", "old"},
	}
	for _, tt := range tests {
		var args tokenStoreArgs
		if err := json.Unmarshal([]byte(tt.input), &args); err != nil {
			t.Fatalf("JSON unmarshal failed for %q: %v", tt.input, err)
		}
		if args.Action != tt.action {
			t.Errorf("input %q: Action = %q, want %q", tt.input, args.Action, tt.action)
		}
		if args.Name != tt.name {
			t.Errorf("input %q: Name = %q, want %q", tt.input, args.Name, tt.name)
		}
	}
}
