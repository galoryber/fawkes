//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestExtractExeName(t *testing.T) {
	tests := []struct {
		name     string
		cmdLine  string
		expected string
	}{
		{
			name:     "empty string",
			cmdLine:  "",
			expected: "",
		},
		{
			name:     "whitespace only",
			cmdLine:  "   ",
			expected: "",
		},
		{
			name:     "simple unquoted exe",
			cmdLine:  "cmd.exe /c dir",
			expected: "cmd.exe",
		},
		{
			name:     "unquoted exe no args",
			cmdLine:  "notepad.exe",
			expected: "notepad.exe",
		},
		{
			name:     "quoted path with args",
			cmdLine:  `"C:\Program Files\app.exe" -arg`,
			expected: `C:\Program Files\app.exe`,
		},
		{
			name:     "quoted path no args",
			cmdLine:  `"C:\Program Files\app.exe"`,
			expected: `C:\Program Files\app.exe`,
		},
		{
			name:     "quoted path with spaces in dir",
			cmdLine:  `"C:\Program Files (x86)\Some App\tool.exe" --verbose`,
			expected: `C:\Program Files (x86)\Some App\tool.exe`,
		},
		{
			name:     "unclosed quote returns rest",
			cmdLine:  `"C:\no closing quote`,
			expected: `C:\no closing quote`,
		},
		{
			name:     "empty quotes",
			cmdLine:  `"" arg1`,
			expected: "",
		},
		{
			name:     "leading whitespace trimmed",
			cmdLine:  "  cmd.exe /c whoami",
			expected: "cmd.exe",
		},
		{
			name:     "leading whitespace with quoted path",
			cmdLine:  `  "C:\tools\app.exe" -flag`,
			expected: `C:\tools\app.exe`,
		},
		{
			name:     "unquoted path with backslashes",
			cmdLine:  `C:\Windows\System32\cmd.exe /c dir`,
			expected: `C:\Windows\System32\cmd.exe`,
		},
		{
			name:     "exe with multiple spaces in args",
			cmdLine:  "powershell.exe -ep bypass -c Get-Process",
			expected: "powershell.exe",
		},
		{
			name:     "single character exe",
			cmdLine:  "a arg1",
			expected: "a",
		},
		{
			name:     "quoted exe with special characters",
			cmdLine:  `"C:\My Tools [v2]\app (1).exe" --run`,
			expected: `C:\My Tools [v2]\app (1).exe`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractExeName(tc.cmdLine)
			if result != tc.expected {
				t.Errorf("extractExeName(%q) = %q, want %q", tc.cmdLine, result, tc.expected)
			}
		})
	}
}

func TestArgueCommand_Name(t *testing.T) {
	cmd := &ArgueCommand{}
	if name := cmd.Name(); name != "argue" {
		t.Errorf("Name() = %q, want %q", name, "argue")
	}
}

func TestArgueCommand_Description(t *testing.T) {
	cmd := &ArgueCommand{}
	desc := cmd.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
}

func TestArgueParams_JSONParsing(t *testing.T) {
	tests := []struct {
		name        string
		jsonInput   string
		wantCommand string
		wantSpoof   string
		wantErr     bool
	}{
		{
			name:        "both fields populated",
			jsonInput:   `{"command":"cmd.exe /c whoami","spoof":"cmd.exe /c echo hello"}`,
			wantCommand: "cmd.exe /c whoami",
			wantSpoof:   "cmd.exe /c echo hello",
		},
		{
			name:        "command only",
			jsonInput:   `{"command":"ipconfig /all"}`,
			wantCommand: "ipconfig /all",
			wantSpoof:   "",
		},
		{
			name:        "empty object",
			jsonInput:   `{}`,
			wantCommand: "",
			wantSpoof:   "",
		},
		{
			name:        "extra fields ignored",
			jsonInput:   `{"command":"net user","spoof":"net help","extra":"ignored"}`,
			wantCommand: "net user",
			wantSpoof:   "net help",
		},
		{
			name:    "invalid JSON",
			jsonInput: `not json`,
			wantErr: true,
		},
		{
			name:        "unicode in values",
			jsonInput:   `{"command":"cmd.exe /c echo \u00e9","spoof":"cmd.exe"}`,
			wantCommand: "cmd.exe /c echo \u00e9",
			wantSpoof:   "cmd.exe",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var params argueParams
			err := json.Unmarshal([]byte(tc.jsonInput), &params)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected JSON parse error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected JSON parse error: %v", err)
			}
			if params.Command != tc.wantCommand {
				t.Errorf("Command = %q, want %q", params.Command, tc.wantCommand)
			}
			if params.Spoof != tc.wantSpoof {
				t.Errorf("Spoof = %q, want %q", params.Spoof, tc.wantSpoof)
			}
		})
	}
}

func TestArgueParams_JSONRoundTrip(t *testing.T) {
	original := argueParams{
		Command: `"C:\Program Files\app.exe" --real-flag`,
		Spoof:   `"C:\Program Files\app.exe" --fake-flag`,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded argueParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Command != original.Command {
		t.Errorf("Command round-trip: got %q, want %q", decoded.Command, original.Command)
	}
	if decoded.Spoof != original.Spoof {
		t.Errorf("Spoof round-trip: got %q, want %q", decoded.Spoof, original.Spoof)
	}
}
