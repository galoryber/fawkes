//go:build windows
// +build windows

package commands

import (
	"testing"
)

func TestExtractExeName_SimpleCommand(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"cmd.exe /c whoami", "cmd.exe"},
		{"powershell.exe -ep bypass", "powershell.exe"},
		{"notepad.exe", "notepad.exe"},
		{"net.exe user admin", "net.exe"},
	}

	for _, tt := range tests {
		got := extractExeName(tt.input)
		if got != tt.want {
			t.Errorf("extractExeName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractExeName_QuotedPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`"C:\Windows\System32\cmd.exe" /c whoami`, `C:\Windows\System32\cmd.exe`},
		{`"C:\Program Files\app.exe" --arg`, `C:\Program Files\app.exe`},
		{`"notepad.exe"`, "notepad.exe"},
	}

	for _, tt := range tests {
		got := extractExeName(tt.input)
		if got != tt.want {
			t.Errorf("extractExeName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractExeName_EdgeCases(t *testing.T) {
	// Empty string
	if got := extractExeName(""); got != "" {
		t.Errorf("extractExeName(\"\") = %q, want \"\"", got)
	}

	// Whitespace only
	if got := extractExeName("   "); got != "" {
		t.Errorf("extractExeName(\"   \") = %q, want \"\"", got)
	}

	// Leading whitespace
	if got := extractExeName("  cmd.exe /c dir"); got != "cmd.exe" {
		t.Errorf("extractExeName(\"  cmd.exe /c dir\") = %q, want \"cmd.exe\"", got)
	}

	// Unclosed quote — returns everything after the opening quote
	if got := extractExeName(`"C:\path\no_close`); got != `C:\path\no_close` {
		t.Errorf("extractExeName(unclosed quote) = %q, want %q", got, `C:\path\no_close`)
	}
}

func TestExtractExeName_NoSpaces(t *testing.T) {
	// Single token without spaces
	got := extractExeName("whoami.exe")
	if got != "whoami.exe" {
		t.Errorf("extractExeName(\"whoami.exe\") = %q, want \"whoami.exe\"", got)
	}
}
