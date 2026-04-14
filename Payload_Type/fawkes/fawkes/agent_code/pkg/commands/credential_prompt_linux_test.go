//go:build linux

package commands

import (
	"testing"
)

func TestFindDialogToolReturnsKnownTool(t *testing.T) {
	tool, path := findDialogTool()
	// On CI/test systems at least one dialog tool may not be installed,
	// but if one is found it must be a known tool name with a valid path.
	if tool == "" && path == "" {
		t.Skip("no GUI dialog tool installed (zenity/kdialog/yad)")
	}
	validTools := map[string]bool{"zenity": true, "kdialog": true, "yad": true}
	if !validTools[tool] {
		t.Errorf("unexpected tool name: %q", tool)
	}
	if path == "" {
		t.Error("tool found but path is empty")
	}
}

func TestBuildDialogArgsZenity(t *testing.T) {
	args := buildDialogArgs("zenity", "Test Title", "Enter password")
	if len(args) != 4 {
		t.Fatalf("expected 4 args, got %d: %v", len(args), args)
	}
	if args[0] != "--entry" {
		t.Errorf("expected --entry, got %s", args[0])
	}
	if args[1] != "--title=Test Title" {
		t.Errorf("expected --title=Test Title, got %s", args[1])
	}
	if args[2] != "--text=Enter password" {
		t.Errorf("expected --text=Enter password, got %s", args[2])
	}
	if args[3] != "--hide-text" {
		t.Errorf("expected --hide-text, got %s", args[3])
	}
}

func TestBuildDialogArgsKdialog(t *testing.T) {
	args := buildDialogArgs("kdialog", "KDE Title", "KDE message")
	if len(args) != 4 {
		t.Fatalf("expected 4 args, got %d: %v", len(args), args)
	}
	if args[0] != "--password" {
		t.Errorf("expected --password, got %s", args[0])
	}
	if args[1] != "KDE message" {
		t.Errorf("expected message text, got %s", args[1])
	}
	if args[2] != "--title" {
		t.Errorf("expected --title, got %s", args[2])
	}
	if args[3] != "KDE Title" {
		t.Errorf("expected title text, got %s", args[3])
	}
}

func TestBuildDialogArgsYad(t *testing.T) {
	args := buildDialogArgs("yad", "YAD Title", "YAD message")
	if len(args) != 4 {
		t.Fatalf("expected 4 args, got %d: %v", len(args), args)
	}
	if args[0] != "--entry" {
		t.Errorf("expected --entry, got %s", args[0])
	}
	if args[3] != "--hide-text" {
		t.Errorf("expected --hide-text, got %s", args[3])
	}
}

func TestBuildDialogArgsUnknown(t *testing.T) {
	args := buildDialogArgs("unknown", "Title", "Message")
	if args != nil {
		t.Errorf("expected nil for unknown tool, got %v", args)
	}
}

func TestBuildDialogArgsEmptyStrings(t *testing.T) {
	args := buildDialogArgs("zenity", "", "")
	if len(args) != 4 {
		t.Fatalf("expected 4 args even with empty strings, got %d", len(args))
	}
	if args[1] != "--title=" {
		t.Errorf("expected --title= with empty value, got %s", args[1])
	}
}

func TestBuildDialogArgsSpecialChars(t *testing.T) {
	args := buildDialogArgs("zenity", "Title with 'quotes'", "Message with \"double quotes\"")
	if len(args) != 4 {
		t.Fatalf("expected 4 args, got %d", len(args))
	}
	if args[1] != "--title=Title with 'quotes'" {
		t.Errorf("single quotes should pass through: %s", args[1])
	}
	if args[2] != "--text=Message with \"double quotes\"" {
		t.Errorf("double quotes should pass through: %s", args[2])
	}
}

func TestBuildMFADialogArgsZenity(t *testing.T) {
	args := buildMFADialogArgs("zenity", "Verify Identity", "Enter your code")
	if len(args) != 3 {
		t.Fatalf("expected 3 args (no --hide-text), got %d: %v", len(args), args)
	}
	if args[0] != "--entry" {
		t.Errorf("expected --entry, got %s", args[0])
	}
	// MFA dialog should NOT have --hide-text (codes are visible)
	for _, arg := range args {
		if arg == "--hide-text" {
			t.Error("MFA dialog should not hide text — codes are visible")
		}
	}
}

func TestBuildMFADialogArgsKdialog(t *testing.T) {
	args := buildMFADialogArgs("kdialog", "MFA Check", "Enter code")
	if len(args) != 5 {
		t.Fatalf("expected 5 args, got %d: %v", len(args), args)
	}
	if args[0] != "--inputbox" {
		t.Errorf("expected --inputbox (not --password), got %s", args[0])
	}
}

func TestBuildMFADialogArgsYad(t *testing.T) {
	args := buildMFADialogArgs("yad", "Verify", "Code please")
	if len(args) != 3 {
		t.Fatalf("expected 3 args (no --hide-text), got %d: %v", len(args), args)
	}
	for _, arg := range args {
		if arg == "--hide-text" {
			t.Error("MFA dialog should not hide text")
		}
	}
}

func TestBuildMFADialogArgsUnknown(t *testing.T) {
	args := buildMFADialogArgs("unknown", "Title", "Message")
	if args != nil {
		t.Errorf("expected nil for unknown tool, got %v", args)
	}
}
