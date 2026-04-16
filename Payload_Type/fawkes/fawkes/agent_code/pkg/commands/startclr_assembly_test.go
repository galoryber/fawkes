//go:build windows
// +build windows

package commands

import (
	"testing"
)

func TestParseAssemblyArgs_Empty(t *testing.T) {
	args := parseAssemblyArgs("")
	if len(args) != 0 {
		t.Errorf("Expected 0 args for empty string, got %d", len(args))
	}
}

func TestParseAssemblyArgs_Single(t *testing.T) {
	args := parseAssemblyArgs("hello")
	if len(args) != 1 || args[0] != "hello" {
		t.Errorf("Expected [hello], got %v", args)
	}
}

func TestParseAssemblyArgs_Multiple(t *testing.T) {
	args := parseAssemblyArgs("arg1 arg2 arg3")
	if len(args) != 3 {
		t.Fatalf("Expected 3 args, got %d: %v", len(args), args)
	}
	if args[0] != "arg1" || args[1] != "arg2" || args[2] != "arg3" {
		t.Errorf("Unexpected args: %v", args)
	}
}

func TestParseAssemblyArgs_QuotedString(t *testing.T) {
	args := parseAssemblyArgs(`--user "John Doe" --flag`)
	if len(args) != 3 {
		t.Fatalf("Expected 3 args, got %d: %v", len(args), args)
	}
	if args[0] != "--user" {
		t.Errorf("args[0] = %q, want '--user'", args[0])
	}
	if args[1] != "John Doe" {
		t.Errorf("args[1] = %q, want 'John Doe'", args[1])
	}
	if args[2] != "--flag" {
		t.Errorf("args[2] = %q, want '--flag'", args[2])
	}
}

func TestParseAssemblyArgs_SingleQuotes(t *testing.T) {
	args := parseAssemblyArgs("--path '/tmp/my file.txt'")
	if len(args) != 2 {
		t.Fatalf("Expected 2 args, got %d: %v", len(args), args)
	}
	if args[1] != "/tmp/my file.txt" {
		t.Errorf("args[1] = %q, want '/tmp/my file.txt'", args[1])
	}
}

func TestParseAssemblyArgs_MultipleSpaces(t *testing.T) {
	args := parseAssemblyArgs("arg1   arg2   arg3")
	if len(args) != 3 {
		t.Fatalf("Expected 3 args (trimming extra spaces), got %d: %v", len(args), args)
	}
}

func TestExecuteAssemblyAction_EmptyAssembly(t *testing.T) {
	result := executeAssemblyAction("", "")
	if result.Status != "error" {
		t.Errorf("Expected error for empty assembly, got %s", result.Status)
	}
}

func TestExecuteAssemblyAction_InvalidBase64(t *testing.T) {
	result := executeAssemblyAction("not-valid-base64!!!!", "")
	if result.Status != "error" {
		t.Errorf("Expected error for invalid base64, got %s", result.Status)
	}
}
