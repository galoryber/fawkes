//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestInlineAssembly_Name(t *testing.T) {
	cmd := &InlineAssemblyCommand{}
	if got := cmd.Name(); got != "inline-assembly" {
		t.Errorf("Name() = %q, want %q", got, "inline-assembly")
	}
}

func TestInlineAssembly_Description(t *testing.T) {
	cmd := &InlineAssemblyCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestInlineAssembly_InvalidJSON(t *testing.T) {
	cmd := &InlineAssemblyCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestInlineAssembly_MissingAssembly(t *testing.T) {
	cmd := &InlineAssemblyCommand{}
	params, _ := json.Marshal(InlineAssemblyParams{})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Missing assembly should error, got status=%q", result.Status)
	}
}

func TestInlineAssembly_InvalidBase64(t *testing.T) {
	cmd := &InlineAssemblyCommand{}
	params, _ := json.Marshal(InlineAssemblyParams{AssemblyB64: "not-valid!!!"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Invalid base64 should error, got status=%q", result.Status)
	}
}

func TestInlineAssembly_EmptyAfterDecode(t *testing.T) {
	cmd := &InlineAssemblyCommand{}
	params, _ := json.Marshal(InlineAssemblyParams{
		AssemblyB64: base64.StdEncoding.EncodeToString([]byte{}),
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Empty assembly should error, got status=%q", result.Status)
	}
}

func TestInlineAssembly_ParamParsing(t *testing.T) {
	input := `{"assembly_b64":"AQID","arguments":"--verbose --output test.txt"}`
	var params InlineAssemblyParams
	if err := json.Unmarshal([]byte(input), &params); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if params.AssemblyB64 != "AQID" {
		t.Errorf("AssemblyB64 = %q, want %q", params.AssemblyB64, "AQID")
	}
	if params.Arguments != "--verbose --output test.txt" {
		t.Errorf("Arguments = %q, want %q", params.Arguments, "--verbose --output test.txt")
	}
}
