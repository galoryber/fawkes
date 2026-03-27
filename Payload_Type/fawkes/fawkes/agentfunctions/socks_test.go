package agentfunctions

import (
	"reflect"
	"testing"
)

func TestSplitArgs_SimpleArgs(t *testing.T) {
	got := splitArgs("hello world")
	want := []string{"hello", "world"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitArgs(%q) = %v, want %v", "hello world", got, want)
	}
}

func TestSplitArgs_DoubleQuoted(t *testing.T) {
	got := splitArgs(`cmd "arg with spaces" next`)
	want := []string{"cmd", "arg with spaces", "next"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSplitArgs_SingleQuoted(t *testing.T) {
	got := splitArgs(`cmd 'arg with spaces' next`)
	want := []string{"cmd", "arg with spaces", "next"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSplitArgs_Empty(t *testing.T) {
	got := splitArgs("")
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestSplitArgs_OnlySpaces(t *testing.T) {
	got := splitArgs("   ")
	if len(got) != 0 {
		t.Errorf("expected empty for whitespace-only, got %v", got)
	}
}

func TestSplitArgs_SingleArg(t *testing.T) {
	got := splitArgs("single")
	want := []string{"single"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSplitArgs_QuotedSingleArg(t *testing.T) {
	got := splitArgs(`"hello world"`)
	want := []string{"hello world"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSplitArgs_EmptyQuotes(t *testing.T) {
	got := splitArgs(`cmd "" next`)
	want := []string{"cmd", "next"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSplitArgs_TabSeparated(t *testing.T) {
	got := splitArgs("a\tb\tc")
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSplitArgs_MixedQuotes(t *testing.T) {
	got := splitArgs(`cmd "double" 'single' plain`)
	want := []string{"cmd", "double", "single", "plain"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSplitArgs_MultipleSpaces(t *testing.T) {
	got := splitArgs("  a   b   c  ")
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSplitArgs_QuoteInMiddle(t *testing.T) {
	got := splitArgs(`before"quoted part"after`)
	want := []string{"beforequoted partafter"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSplitArgs_SpecialCharsInQuotes(t *testing.T) {
	got := splitArgs(`cmd "path/to/file with spaces.txt" -flag`)
	want := []string{"cmd", "path/to/file with spaces.txt", "-flag"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSplitArgs_UnterminatedQuote(t *testing.T) {
	got := splitArgs(`cmd "unterminated`)
	want := []string{"cmd", "unterminated"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
