package commands

import (
	"encoding/json"
	"testing"
)

func TestKillParams_JSONParsing(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantPID int
		wantErr bool
	}{
		{"valid PID", `{"pid": 1234}`, 1234, false},
		{"zero PID", `{"pid": 0}`, 0, false},
		{"negative PID", `{"pid": -1}`, -1, false},
		{"large PID", `{"pid": 99999}`, 99999, false},
		{"empty JSON", `{}`, 0, false},
		{"invalid JSON", `not json`, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params KillParams
			err := json.Unmarshal([]byte(tt.input), &params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && params.PID != tt.wantPID {
				t.Errorf("PID = %d, want %d", params.PID, tt.wantPID)
			}
		})
	}
}

func TestKillParams_JSONRoundtrip(t *testing.T) {
	original := KillParams{PID: 42}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded KillParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PID != original.PID {
		t.Errorf("roundtrip PID = %d, want %d", decoded.PID, original.PID)
	}
}
