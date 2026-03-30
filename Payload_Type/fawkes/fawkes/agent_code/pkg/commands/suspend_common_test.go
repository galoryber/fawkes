package commands

import (
	"encoding/json"
	"testing"
)

func TestSuspendParams_JSONParsing(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantAction string
		wantPID    int
		wantErr    bool
	}{
		{"suspend", `{"action":"suspend","pid":1234}`, "suspend", 1234, false},
		{"resume", `{"action":"resume","pid":5678}`, "resume", 5678, false},
		{"empty action", `{"pid":1234}`, "", 1234, false},
		{"empty PID", `{"action":"suspend"}`, "suspend", 0, false},
		{"invalid JSON", `{bad`, "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params SuspendParams
			err := json.Unmarshal([]byte(tt.input), &params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				if params.Action != tt.wantAction {
					t.Errorf("Action = %q, want %q", params.Action, tt.wantAction)
				}
				if params.PID != tt.wantPID {
					t.Errorf("PID = %d, want %d", params.PID, tt.wantPID)
				}
			}
		})
	}
}

func TestSuspendParams_JSONRoundtrip(t *testing.T) {
	original := SuspendParams{Action: "suspend", PID: 42}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded SuspendParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Action != original.Action || decoded.PID != original.PID {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", decoded, original)
	}
}
