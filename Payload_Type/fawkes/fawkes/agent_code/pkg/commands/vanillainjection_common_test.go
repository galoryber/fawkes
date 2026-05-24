package commands

import (
	"encoding/json"
	"testing"
)

func TestIsMigrateAction(t *testing.T) {
	tests := []struct {
		action string
		want   bool
	}{
		{"migrate", true},
		{"Migrate", true},
		{"MIGRATE", true},
		{"inject", false},
		{"", false},
		{"migration", false},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			if got := isMigrateAction(tt.action); got != tt.want {
				t.Errorf("isMigrateAction(%q) = %v, want %v", tt.action, got, tt.want)
			}
		})
	}
}

func TestVanillaInjectionParams_JSON(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantSC string
		wantP  int
		wantA  string
		wantT  string
	}{
		{"full", `{"shellcode_b64":"AQID","pid":1234,"action":"inject","target":"auto"}`, "AQID", 1234, "inject", "auto"},
		{"migrate", `{"shellcode_b64":"BAUG","pid":99,"action":"migrate"}`, "BAUG", 99, "migrate", ""},
		{"minimal", `{"shellcode_b64":"AA==","pid":1}`, "AA==", 1, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p VanillaInjectionParams
			if err := json.Unmarshal([]byte(tt.input), &p); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if p.ShellcodeB64 != tt.wantSC {
				t.Errorf("ShellcodeB64 = %q, want %q", p.ShellcodeB64, tt.wantSC)
			}
			if p.PID != tt.wantP {
				t.Errorf("PID = %d, want %d", p.PID, tt.wantP)
			}
			if p.Action != tt.wantA {
				t.Errorf("Action = %q, want %q", p.Action, tt.wantA)
			}
			if p.Target != tt.wantT {
				t.Errorf("Target = %q, want %q", p.Target, tt.wantT)
			}
		})
	}
}
