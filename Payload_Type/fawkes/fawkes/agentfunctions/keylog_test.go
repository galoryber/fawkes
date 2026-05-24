package agentfunctions

import (
	"testing"
)

func TestWindowSectionRegex_MatchesValidSection(t *testing.T) {
	input := "[14:30:25] --- Chrome - Google Search ---"
	matches := windowSectionRegex.FindStringSubmatch(input)
	if len(matches) != 3 {
		t.Fatalf("expected 3 groups, got %d: %v", len(matches), matches)
	}
	if matches[1] != "14:30:25" {
		t.Errorf("timestamp = %q, want 14:30:25", matches[1])
	}
	if matches[2] != "Chrome - Google Search" {
		t.Errorf("window title = %q, want 'Chrome - Google Search'", matches[2])
	}
}

func TestWindowSectionRegex_MatchesMultipleSections(t *testing.T) {
	input := `[09:00:00] --- Notepad ---
some keystrokes here
[09:01:30] --- cmd.exe ---
dir /s`

	matches := windowSectionRegex.FindAllStringSubmatch(input, -1)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	if matches[0][2] != "Notepad" {
		t.Errorf("first window = %q, want Notepad", matches[0][2])
	}
	if matches[1][2] != "cmd.exe" {
		t.Errorf("second window = %q, want cmd.exe", matches[1][2])
	}
}

func TestWindowSectionRegex_NoMatch(t *testing.T) {
	inputs := []string{
		"plain text without sections",
		"[invalid] --- no timestamp ---",
		"[12:34] --- short time ---", // needs HH:MM:SS format
		"",
	}
	for _, input := range inputs {
		matches := windowSectionRegex.FindStringSubmatch(input)
		if len(matches) != 0 {
			t.Errorf("expected no match for %q, got %v", input, matches)
		}
	}
}

func TestWindowSectionRegex_SpecialCharacters(t *testing.T) {
	input := "[23:59:59] --- C:\\Users\\admin (Administrator) ---"
	matches := windowSectionRegex.FindStringSubmatch(input)
	if len(matches) != 3 {
		t.Fatalf("expected match for special chars, got %d groups", len(matches))
	}
	if matches[2] != `C:\Users\admin (Administrator)` {
		t.Errorf("window = %q", matches[2])
	}
}

func TestWindowSectionRegex_MidnightTimestamp(t *testing.T) {
	input := "[00:00:00] --- Desktop ---"
	matches := windowSectionRegex.FindStringSubmatch(input)
	if len(matches) != 3 {
		t.Fatalf("expected match for midnight")
	}
	if matches[1] != "00:00:00" {
		t.Errorf("timestamp = %q", matches[1])
	}
}
