//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestStartCLRCommandName(t *testing.T) {
	assertCommandName(t, &StartCLRCommand{}, "start-clr")
}

func TestStartCLRCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &StartCLRCommand{})
}

func TestStartCLRParamsUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		wantAmsi string
		wantEtw  string
	}{
		{"defaults", `{}`, "", ""},
		{"autopatch", `{"amsi_patch":"Autopatch","etw_patch":"Autopatch"}`, "Autopatch", "Autopatch"},
		{"ret_patch", `{"amsi_patch":"Ret Patch","etw_patch":"Ret Patch"}`, "Ret Patch", "Ret Patch"},
		{"hwbp", `{"amsi_patch":"Hardware Breakpoint","etw_patch":"Hardware Breakpoint"}`, "Hardware Breakpoint", "Hardware Breakpoint"},
		{"none", `{"amsi_patch":"None","etw_patch":"None"}`, "None", "None"},
		{"mixed", `{"amsi_patch":"Autopatch","etw_patch":"None"}`, "Autopatch", "None"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params StartCLRParams
			if err := json.Unmarshal([]byte(tt.json), &params); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if params.AmsiPatch != tt.wantAmsi {
				t.Errorf("AmsiPatch = %q, want %q", params.AmsiPatch, tt.wantAmsi)
			}
			if params.EtwPatch != tt.wantEtw {
				t.Errorf("EtwPatch = %q, want %q", params.EtwPatch, tt.wantEtw)
			}
		})
	}
}

func TestStartCLRParamsDefaults(t *testing.T) {
	// When params are empty strings, the Execute function defaults them to "None"
	var params StartCLRParams
	if err := json.Unmarshal([]byte(`{}`), &params); err != nil {
		t.Fatal(err)
	}
	// Empty string should be treated as "None" by Execute logic
	if params.AmsiPatch != "" {
		t.Errorf("empty JSON should unmarshal AmsiPatch to empty string, got %q", params.AmsiPatch)
	}
}
