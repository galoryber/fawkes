package commands

import (
	"strings"
	"testing"
)

// --- credIndentLines ---

func TestCredIndentLines_Basic(t *testing.T) {
	result := credIndentLines("line1\nline2\nline3", "  ")
	lines := strings.Split(result, "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	for i, line := range lines {
		if !strings.HasPrefix(line, "  ") {
			t.Errorf("line %d not indented: %q", i, line)
		}
	}
}

func TestCredIndentLines_Empty(t *testing.T) {
	result := credIndentLines("", "    ")
	if result != "" {
		t.Errorf("expected empty string for empty input, got %q", result)
	}
}

func TestCredIndentLines_EmptyLines(t *testing.T) {
	result := credIndentLines("line1\n\nline3", ">>")
	lines := strings.Split(result, "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	// Empty lines should NOT be indented
	if lines[1] != "" {
		t.Errorf("empty line should stay empty, got %q", lines[1])
	}
	if !strings.HasPrefix(lines[0], ">>") {
		t.Errorf("non-empty line should be indented: %q", lines[0])
	}
}

func TestCredIndentLines_SingleLine(t *testing.T) {
	result := credIndentLines("hello", "    ")
	if result != "    hello" {
		t.Errorf("expected '    hello', got %q", result)
	}
}

func TestCredIndentLines_DifferentPrefixes(t *testing.T) {
	tests := []struct {
		prefix string
	}{
		{"  "},
		{"    "},
		{"\t"},
		{"| "},
	}
	for _, tc := range tests {
		result := credIndentLines("test", tc.prefix)
		if !strings.HasPrefix(result, tc.prefix) {
			t.Errorf("expected prefix %q, got %q", tc.prefix, result)
		}
	}
}
