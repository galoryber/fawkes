//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestAmcacheParams_JSONParsing(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantAction string
		wantName   string
		wantCount  int
		wantErr    bool
	}{
		{"query", `{"action":"query","count":100}`, "query", "", 100, false},
		{"search", `{"action":"search","name":"cmd.exe"}`, "search", "cmd.exe", 0, false},
		{"delete", `{"action":"delete","name":"suspicious.exe"}`, "delete", "suspicious.exe", 0, false},
		{"defaults", `{}`, "", "", 0, false},
		{"invalid", `{bad`, "", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params amcacheParams
			err := json.Unmarshal([]byte(tt.input), &params)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				if params.Action != tt.wantAction {
					t.Errorf("Action = %q, want %q", params.Action, tt.wantAction)
				}
				if params.Name != tt.wantName {
					t.Errorf("Name = %q, want %q", params.Name, tt.wantName)
				}
				if params.Count != tt.wantCount {
					t.Errorf("Count = %d, want %d", params.Count, tt.wantCount)
				}
			}
		})
	}
}

func TestAmcacheOutputEntry_JSON(t *testing.T) {
	entry := amcacheOutputEntry{
		Index:        1,
		LastModified: "2026-03-29T00:00:00Z",
		Path:         "C:\\Windows\\System32\\cmd.exe",
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var decoded amcacheOutputEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Index != entry.Index || decoded.Path != entry.Path || decoded.LastModified != entry.LastModified {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", decoded, entry)
	}
}

func TestAmcacheCommand_Name(t *testing.T) {
	cmd := &AmcacheCommand{}
	if cmd.Name() != "amcache" {
		t.Errorf("Name() = %q, want amcache", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}
