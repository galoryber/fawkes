//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestCredmanArgs_JSONParsing(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantAction string
		wantFilter string
		wantErr    bool
	}{
		{"list action", `{"action":"list"}`, "list", "", false},
		{"dump action", `{"action":"dump"}`, "dump", "", false},
		{"with filter", `{"action":"list","filter":"Microsoft*"}`, "list", "Microsoft*", false},
		{"empty", `{}`, "", "", false},
		{"invalid JSON", `{bad`, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args credmanArgs
			err := json.Unmarshal([]byte(tt.input), &args)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				if args.Action != tt.wantAction {
					t.Errorf("Action = %q, want %q", args.Action, tt.wantAction)
				}
				if args.Filter != tt.wantFilter {
					t.Errorf("Filter = %q, want %q", args.Filter, tt.wantFilter)
				}
			}
		})
	}
}

func TestCredmanCommand_Name(t *testing.T) {
	cmd := &CredmanCommand{}
	if cmd.Name() != "credman" {
		t.Errorf("Name() = %q, want credman", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestCredentialStructSize(t *testing.T) {
	// Verify the credential struct can be instantiated
	var cred credential
	cred.Type = 1
	cred.CredentialBlobSize = 0
	if cred.Type != 1 {
		t.Error("credential struct field assignment failed")
	}
}
