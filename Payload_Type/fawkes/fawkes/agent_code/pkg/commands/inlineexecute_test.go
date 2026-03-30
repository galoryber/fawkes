//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestInlineExecuteCommandName(t *testing.T) {
	cmd := &InlineExecuteCommand{}
	if cmd.Name() != "inline-execute" {
		t.Errorf("Name() = %q, want inline-execute", cmd.Name())
	}
}

func TestInlineExecuteCommandDescription(t *testing.T) {
	cmd := &InlineExecuteCommand{}
	if cmd.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestInlineExecuteParams_JSON(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantBOF    string
		wantEntry  string
		wantNArgs  int
	}{
		{
			name:      "full params",
			input:     `{"bof_b64":"AAAA","entry_point":"go","arguments":["z/tmp","i80"]}`,
			wantBOF:   "AAAA",
			wantEntry: "go",
			wantNArgs: 2,
		},
		{
			name:      "minimal",
			input:     `{"bof_b64":"AQID"}`,
			wantBOF:   "AQID",
			wantEntry: "",
			wantNArgs: 0,
		},
		{
			name:      "empty",
			input:     `{}`,
			wantBOF:   "",
			wantEntry: "",
			wantNArgs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p InlineExecuteParams
			if err := json.Unmarshal([]byte(tt.input), &p); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if p.BOFB64 != tt.wantBOF {
				t.Errorf("BOFB64 = %q, want %q", p.BOFB64, tt.wantBOF)
			}
			if p.EntryPoint != tt.wantEntry {
				t.Errorf("EntryPoint = %q, want %q", p.EntryPoint, tt.wantEntry)
			}
			if len(p.Arguments) != tt.wantNArgs {
				t.Errorf("Arguments len = %d, want %d", len(p.Arguments), tt.wantNArgs)
			}
		})
	}
}

func TestInlineExecuteParams_RoundTrip(t *testing.T) {
	original := InlineExecuteParams{
		BOFB64:     "dGVzdA==",
		EntryPoint: "go",
		Arguments:  []string{"zvalue", "i80"},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded InlineExecuteParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.BOFB64 != original.BOFB64 {
		t.Errorf("BOFB64 mismatch")
	}
	if decoded.EntryPoint != original.EntryPoint {
		t.Errorf("EntryPoint mismatch")
	}
	if len(decoded.Arguments) != len(original.Arguments) {
		t.Errorf("Arguments len mismatch")
	}
}
