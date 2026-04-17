package agentfunctions

import (
	"testing"
)

func TestClipboardDetectedCredentialPatterns_None(t *testing.T) {
	result := clipboardDetectedCredentialPatterns("hello world, nothing suspicious here")
	if len(result) != 0 {
		t.Errorf("expected no patterns, got %v", result)
	}
}

func TestClipboardDetectedCredentialPatterns_Empty(t *testing.T) {
	result := clipboardDetectedCredentialPatterns("")
	if len(result) != 0 {
		t.Errorf("expected no patterns for empty input, got %v", result)
	}
}

func TestClipboardDetectedCredentialPatterns_NTLMHash(t *testing.T) {
	result := clipboardDetectedCredentialPatterns("NTLM Hash: aad3b435b51404eeaad3b435b51404ee")
	if len(result) != 1 || result[0] != "NTLM Hash" {
		t.Errorf("expected [NTLM Hash], got %v", result)
	}
}

func TestClipboardDetectedCredentialPatterns_NTHash(t *testing.T) {
	result := clipboardDetectedCredentialPatterns("NT Hash detected in output")
	if len(result) != 1 || result[0] != "NT Hash" {
		t.Errorf("expected [NT Hash], got %v", result)
	}
}

func TestClipboardDetectedCredentialPatterns_PasswordLike(t *testing.T) {
	result := clipboardDetectedCredentialPatterns("Password-like string found")
	if len(result) != 1 || result[0] != "Password-like" {
		t.Errorf("expected [Password-like], got %v", result)
	}
}

func TestClipboardDetectedCredentialPatterns_APIKey(t *testing.T) {
	result := clipboardDetectedCredentialPatterns("API Key: sk-abc123")
	if len(result) != 1 || result[0] != "API Key" {
		t.Errorf("expected [API Key], got %v", result)
	}
}

func TestClipboardDetectedCredentialPatterns_AWSKey(t *testing.T) {
	result := clipboardDetectedCredentialPatterns("AWS Key AKIA1234567890ABCDEF")
	if len(result) != 1 || result[0] != "AWS Key" {
		t.Errorf("expected [AWS Key], got %v", result)
	}
}

func TestClipboardDetectedCredentialPatterns_PrivateKey(t *testing.T) {
	result := clipboardDetectedCredentialPatterns("-----BEGIN RSA Private Key-----")
	if len(result) != 1 || result[0] != "Private Key" {
		t.Errorf("expected [Private Key], got %v", result)
	}
}

func TestClipboardDetectedCredentialPatterns_BearerToken(t *testing.T) {
	result := clipboardDetectedCredentialPatterns("Authorization: Bearer Token eyJhbGc...")
	if len(result) != 1 || result[0] != "Bearer Token" {
		t.Errorf("expected [Bearer Token], got %v", result)
	}
}

func TestClipboardDetectedCredentialPatterns_Multiple(t *testing.T) {
	result := clipboardDetectedCredentialPatterns("NTLM Hash found; also AWS Key present; Bearer Token in header")
	if len(result) != 3 {
		t.Errorf("expected 3 patterns, got %d: %v", len(result), result)
	}
}

func TestClipboardDetectedCredentialPatterns_AllTags(t *testing.T) {
	text := "NTLM Hash NT Hash Password-like API Key AWS Key Private Key Bearer Token"
	result := clipboardDetectedCredentialPatterns(text)
	if len(result) != len(clipboardCredentialTags) {
		t.Errorf("expected %d patterns, got %d: %v", len(clipboardCredentialTags), len(result), result)
	}
}
