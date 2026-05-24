package agentfunctions

import (
	"testing"
)

func TestParseCredentialPromptResponse_Dialog(t *testing.T) {
	input := "User:     jsmith\nPassword: P@ssw0rd123"
	user, cred, credType := parseCredentialPromptResponse(input)
	if user != "jsmith" {
		t.Errorf("expected jsmith, got %q", user)
	}
	if cred != "P@ssw0rd123" {
		t.Errorf("expected P@ssw0rd123, got %q", cred)
	}
	if credType != "dialog" {
		t.Errorf("expected dialog, got %q", credType)
	}
}

func TestParseCredentialPromptResponse_MFAPhish(t *testing.T) {
	input := "User:     admin@corp.com\nCode:     123456"
	user, cred, credType := parseCredentialPromptResponse(input)
	if user != "admin@corp.com" {
		t.Errorf("expected admin@corp.com, got %q", user)
	}
	if cred != "123456" {
		t.Errorf("expected 123456, got %q", cred)
	}
	if credType != "mfa-phish" {
		t.Errorf("expected mfa-phish, got %q", credType)
	}
}

func TestParseCredentialPromptResponse_Empty(t *testing.T) {
	user, cred, _ := parseCredentialPromptResponse("")
	if user != "" || cred != "" {
		t.Errorf("expected empty results, got user=%q cred=%q", user, cred)
	}
}

func TestParseCredentialPromptResponse_UserOnly(t *testing.T) {
	input := "User:     admin"
	user, cred, _ := parseCredentialPromptResponse(input)
	if user != "admin" {
		t.Errorf("expected admin, got %q", user)
	}
	if cred != "" {
		t.Errorf("expected empty credential, got %q", cred)
	}
}

func TestParseCredentialPromptResponse_ExtraWhitespace(t *testing.T) {
	input := "  User:     jsmith  \n  Password:    secret  "
	user, cred, credType := parseCredentialPromptResponse(input)
	if user != "jsmith" {
		t.Errorf("expected jsmith, got %q", user)
	}
	if cred != "secret" {
		t.Errorf("expected secret, got %q", cred)
	}
	if credType != "dialog" {
		t.Errorf("expected dialog, got %q", credType)
	}
}

func TestParseCredentialPromptResponse_NoPrefix(t *testing.T) {
	input := "Some random output\nwithout user/password lines"
	user, cred, _ := parseCredentialPromptResponse(input)
	if user != "" || cred != "" {
		t.Errorf("expected empty results for non-matching input, got user=%q cred=%q", user, cred)
	}
}

func TestCredentialPromptDefaultTitle_Empty(t *testing.T) {
	if title := credentialPromptDefaultTitle(""); title != "Update Required" {
		t.Errorf("expected 'Update Required', got %q", title)
	}
}

func TestCredentialPromptDefaultTitle_Custom(t *testing.T) {
	if title := credentialPromptDefaultTitle("Security Alert"); title != "Security Alert" {
		t.Errorf("expected 'Security Alert', got %q", title)
	}
}
