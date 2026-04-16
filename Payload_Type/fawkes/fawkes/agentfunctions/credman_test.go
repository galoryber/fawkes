package agentfunctions

import (
	"testing"
)

func TestParseCredmanBlocks_SingleBlock(t *testing.T) {
	input := `--- WindowsLive:target=virtualapp/didlogical ---
  Type: Generic
  Username: 02rmtnfmaa
  Password: s3cretPass!`

	creds := parseCredmanBlocks(input)
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].Account != "02rmtnfmaa" {
		t.Errorf("Account = %q, want %q", creds[0].Account, "02rmtnfmaa")
	}
	if creds[0].Credential != "s3cretPass!" {
		t.Errorf("Credential = %q, want %q", creds[0].Credential, "s3cretPass!")
	}
	if creds[0].Realm != "WindowsLive:target=virtualapp/didlogical" {
		t.Errorf("Realm = %q", creds[0].Realm)
	}
	if creds[0].CredentialType != "plaintext" {
		t.Errorf("Type = %q, want plaintext", creds[0].CredentialType)
	}
	if creds[0].Comment != "credman dump (Generic)" {
		t.Errorf("Comment = %q", creds[0].Comment)
	}
}

func TestParseCredmanBlocks_MultipleBlocks(t *testing.T) {
	input := `--- target1 ---
  Type: Domain Password
  Username: admin
  Password: Pass1
--- target2 ---
  Type: Generic
  Username: user2
  Password: Pass2`

	creds := parseCredmanBlocks(input)
	if len(creds) != 2 {
		t.Fatalf("expected 2 creds, got %d", len(creds))
	}
	if creds[0].Account != "admin" {
		t.Errorf("creds[0].Account = %q", creds[0].Account)
	}
	if creds[1].Account != "user2" {
		t.Errorf("creds[1].Account = %q", creds[1].Account)
	}
}

func TestParseCredmanBlocks_NoPassword(t *testing.T) {
	input := `--- target ---
  Type: Generic
  Username: admin`

	creds := parseCredmanBlocks(input)
	if len(creds) != 0 {
		t.Errorf("expected 0 creds (no password), got %d", len(creds))
	}
}

func TestParseCredmanBlocks_NoUsername(t *testing.T) {
	input := `--- target ---
  Type: Generic
  Password: secret`

	creds := parseCredmanBlocks(input)
	if len(creds) != 0 {
		t.Errorf("expected 0 creds (no username), got %d", len(creds))
	}
}

func TestParseCredmanBlocks_SkipsSummary(t *testing.T) {
	input := `--- target ---
  Type: Generic
  Username: admin
  Password: Pass1
--- Summary: 1 credential found ---`

	creds := parseCredmanBlocks(input)
	if len(creds) != 1 {
		t.Errorf("expected 1 cred (summary skipped), got %d", len(creds))
	}
}

func TestParseCredmanBlocks_Empty(t *testing.T) {
	creds := parseCredmanBlocks("")
	if len(creds) != 0 {
		t.Errorf("expected 0 creds for empty input, got %d", len(creds))
	}
}

func TestDetectClipboardCredentialPatterns_NTLMHash(t *testing.T) {
	text := "Clipboard contains NTLM Hash: aad3b435b51404eeaad3b435b51404ee"
	patterns := detectClipboardCredentialPatterns(text)
	if len(patterns) != 1 || patterns[0] != "NTLM Hash" {
		t.Errorf("expected [NTLM Hash], got %v", patterns)
	}
}

func TestDetectClipboardCredentialPatterns_Multiple(t *testing.T) {
	text := "Found AWS Key AKIAIOSFODNN7EXAMPLE and also a Bearer Token for API access"
	patterns := detectClipboardCredentialPatterns(text)
	if len(patterns) != 2 {
		t.Errorf("expected 2 patterns, got %d: %v", len(patterns), patterns)
	}
}

func TestDetectClipboardCredentialPatterns_None(t *testing.T) {
	text := "Normal clipboard text without any secrets"
	patterns := detectClipboardCredentialPatterns(text)
	if len(patterns) != 0 {
		t.Errorf("expected 0 patterns, got %v", patterns)
	}
}

func TestDetectClipboardCredentialPatterns_AllPatterns(t *testing.T) {
	text := "NTLM Hash NT Hash Password-like API Key AWS Key Private Key Bearer Token"
	patterns := detectClipboardCredentialPatterns(text)
	if len(patterns) != 7 {
		t.Errorf("expected 7 patterns, got %d: %v", len(patterns), patterns)
	}
}

func TestDetectClipboardCredentialPatterns_Empty(t *testing.T) {
	patterns := detectClipboardCredentialPatterns("")
	if len(patterns) != 0 {
		t.Errorf("expected 0 for empty, got %v", patterns)
	}
}
