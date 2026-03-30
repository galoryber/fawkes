//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestDpapiArgs_JSONParsing(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantAction string
		wantBlob   string
		wantErr    bool
	}{
		{"decrypt with blob", `{"action":"decrypt","blob":"dGVzdA=="}`, "decrypt", "dGVzdA==", false},
		{"masterkeys", `{"action":"masterkeys","path":"C:\\Users\\test"}`, "masterkeys", "", false},
		{"chrome-key", `{"action":"chrome-key"}`, "chrome-key", "", false},
		{"empty action defaults", `{"blob":"data"}`, "", "data", false},
		{"invalid JSON", `{bad`, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args dpapiArgs
			err := json.Unmarshal([]byte(tt.input), &args)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				if args.Action != tt.wantAction {
					t.Errorf("Action = %q, want %q", args.Action, tt.wantAction)
				}
				if args.Blob != tt.wantBlob {
					t.Errorf("Blob = %q, want %q", args.Blob, tt.wantBlob)
				}
			}
		})
	}
}

func TestDpapiArgs_AllFields(t *testing.T) {
	input := `{"action":"decrypt","blob":"YWJj","entropy":"ZGVm","path":"C:\\temp"}`
	var args dpapiArgs
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatal(err)
	}
	if args.Action != "decrypt" || args.Blob != "YWJj" || args.Entropy != "ZGVm" || args.Path != "C:\\temp" {
		t.Errorf("unexpected args: %+v", args)
	}
}

func TestDpapiCommand_Name(t *testing.T) {
	cmd := &DpapiCommand{}
	if cmd.Name() != "dpapi" {
		t.Errorf("Name() = %q, want dpapi", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}
