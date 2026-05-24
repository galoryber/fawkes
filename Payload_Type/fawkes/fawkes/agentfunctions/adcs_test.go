package agentfunctions

import (
	"testing"
)

// --- truncateString Tests ---

func TestTruncateString_Short(t *testing.T) {
	got := truncateString("hello", 10)
	if got != "hello" {
		t.Errorf("truncateString = %q, want %q", got, "hello")
	}
}

func TestTruncateString_ExactLimit(t *testing.T) {
	got := truncateString("hello", 5)
	if got != "hello" {
		t.Errorf("truncateString = %q, want %q", got, "hello")
	}
}

func TestTruncateString_Exceeds(t *testing.T) {
	got := truncateString("hello world", 5)
	if got != "hello..." {
		t.Errorf("truncateString = %q, want %q", got, "hello...")
	}
}

func TestTruncateString_Empty(t *testing.T) {
	got := truncateString("", 5)
	if got != "" {
		t.Errorf("truncateString = %q, want empty", got)
	}
}

func TestTruncateString_SingleChar(t *testing.T) {
	got := truncateString("x", 1)
	if got != "x" {
		t.Errorf("truncateString = %q, want %q", got, "x")
	}
}

func TestTruncateString_ZeroLimit(t *testing.T) {
	got := truncateString("hello", 0)
	if got != "..." {
		t.Errorf("truncateString = %q, want %q", got, "...")
	}
}

func TestTruncateString_LongString(t *testing.T) {
	input := "This is a very long string that should be truncated to a shorter length"
	got := truncateString(input, 20)
	if len(got) != 23 { // 20 + "..."
		t.Errorf("truncateString length = %d, want 23", len(got))
	}
	if got != "This is a very long ..." {
		t.Errorf("truncateString = %q", got)
	}
}
