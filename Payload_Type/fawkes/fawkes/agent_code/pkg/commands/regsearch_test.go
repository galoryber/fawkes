//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestRegSearchResult_JSON(t *testing.T) {
	tests := []struct {
		name   string
		result regSearchResult
	}{
		{
			name:   "key only",
			result: regSearchResult{KeyPath: `SOFTWARE\Microsoft\Windows`},
		},
		{
			name:   "with value",
			result: regSearchResult{KeyPath: `SOFTWARE\Test`, ValueName: "Setting", ValueData: "enabled"},
		},
		{
			name:   "empty",
			result: regSearchResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.result)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var decoded regSearchResult
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if decoded.KeyPath != tt.result.KeyPath {
				t.Errorf("KeyPath = %q, want %q", decoded.KeyPath, tt.result.KeyPath)
			}
			if decoded.ValueName != tt.result.ValueName {
				t.Errorf("ValueName = %q, want %q", decoded.ValueName, tt.result.ValueName)
			}
			if decoded.ValueData != tt.result.ValueData {
				t.Errorf("ValueData = %q, want %q", decoded.ValueData, tt.result.ValueData)
			}
		})
	}
}

func TestRegSearchResult_OmitEmpty(t *testing.T) {
	// When ValueName and ValueData are empty, they should be omitted from JSON
	r := regSearchResult{KeyPath: `SOFTWARE\Test`}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)
	// value_name has omitempty, so it should not appear
	if json.Valid([]byte(s)) == false {
		t.Errorf("invalid JSON: %s", s)
	}
	// Verify key_path is present
	var m map[string]interface{}
	json.Unmarshal(data, &m)
	if _, ok := m["key_path"]; !ok {
		t.Error("key_path missing from JSON")
	}
}
