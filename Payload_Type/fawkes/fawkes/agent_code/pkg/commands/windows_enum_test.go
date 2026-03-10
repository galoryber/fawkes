//go:build windows

package commands

import (
	"testing"
)

func TestWetrunc_Short(t *testing.T) {
	// String shorter than max — returned as-is
	got := wetrunc("hello", 10)
	if got != "hello" {
		t.Errorf("wetrunc(\"hello\", 10) = %q, want \"hello\"", got)
	}
}

func TestWetrunc_ExactLength(t *testing.T) {
	got := wetrunc("hello", 5)
	if got != "hello" {
		t.Errorf("wetrunc(\"hello\", 5) = %q, want \"hello\"", got)
	}
}

func TestWetrunc_Truncated(t *testing.T) {
	got := wetrunc("hello world", 8)
	// max=8, so s[:8-3] + "..." = "hello" + "..." = "hello..."
	want := "hello..."
	if got != want {
		t.Errorf("wetrunc(\"hello world\", 8) = %q, want %q", got, want)
	}
}

func TestWetrunc_Empty(t *testing.T) {
	got := wetrunc("", 10)
	if got != "" {
		t.Errorf("wetrunc(\"\", 10) = %q, want \"\"", got)
	}
}

func TestWetrunc_LongString(t *testing.T) {
	input := "Microsoft Edge WebView2 Runtime"
	got := wetrunc(input, 20)
	if len(got) != 20 {
		t.Errorf("len(wetrunc(..., 20)) = %d, want 20", len(got))
	}
	if got[len(got)-3:] != "..." {
		t.Error("truncated string should end with '...'")
	}
}
