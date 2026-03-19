package commands

import (
	"strings"
	"testing"
)

func TestEscapeAppleScriptClean(t *testing.T) {
	result := escapeAppleScript("Hello World")
	if result != "Hello World" {
		t.Errorf("expected unchanged string, got '%s'", result)
	}
}

func TestEscapeAppleScriptQuotes(t *testing.T) {
	result := escapeAppleScript(`He said "hello"`)
	if result != `He said \"hello\"` {
		t.Errorf("expected escaped quotes, got '%s'", result)
	}
}

func TestEscapeAppleScriptBackslash(t *testing.T) {
	result := escapeAppleScript(`path\to\file`)
	if result != `path\\to\\file` {
		t.Errorf("expected escaped backslashes, got '%s'", result)
	}
}

func TestEscapeAppleScriptBoth(t *testing.T) {
	result := escapeAppleScript(`C:\Users\"Admin"`)
	// Step 1: \ → \\ gives C:\\Users\\"Admin"
	// Step 2: " → \" gives C:\\Users\\\"Admin\"
	expected := `C:\\Users\\\"Admin\"`
	if result != expected {
		t.Errorf("expected '%s', got '%s'", expected, result)
	}
}

func TestEscapeAppleScriptEmpty(t *testing.T) {
	result := escapeAppleScript("")
	if result != "" {
		t.Errorf("expected empty string, got '%s'", result)
	}
}

func TestBuildCredPromptScriptBasic(t *testing.T) {
	result := buildCredPromptScript("System Preferences", "Enter your password", "caution")
	if !strings.Contains(result, "Enter your password") {
		t.Error("expected message in script")
	}
	if !strings.Contains(result, "System Preferences") {
		t.Error("expected title in script")
	}
	if !strings.Contains(result, "with hidden answer") {
		t.Error("expected hidden answer in script")
	}
	if !strings.Contains(result, "caution") {
		t.Error("expected icon in script")
	}
}

func TestBuildCredPromptScriptQuoteEscaping(t *testing.T) {
	result := buildCredPromptScript(`Title "quoted"`, `Message with "quotes"`, "stop")
	// After escaping, quotes should be preceded by backslash
	if !strings.Contains(result, `\"quoted\"`) {
		t.Errorf("expected escaped quotes in title, got: %s", result)
	}
	if !strings.Contains(result, `\"quotes\"`) {
		t.Errorf("expected escaped quotes in message, got: %s", result)
	}
}

func TestBuildCredPromptScriptContainsReturn(t *testing.T) {
	result := buildCredPromptScript("Title", "Message", "note")
	if !strings.Contains(result, "return theResult") {
		t.Error("expected return statement in script")
	}
}
