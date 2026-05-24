package agentfunctions

import (
	"testing"
)

func TestParseDcsyncOutput_SingleAccount(t *testing.T) {
	input := `[+] Administrator (RID: 500)
  Hash:   Administrator:500:aad3b435b51404ee:8846f7eaee8fb117:::
  AES256: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
  AES128: d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1`

	creds := parseDcsyncOutput(input)
	if len(creds) != 3 {
		t.Fatalf("expected 3 credentials, got %d", len(creds))
	}
	if creds[0].Account != "Administrator" {
		t.Errorf("expected account Administrator, got %q", creds[0].Account)
	}
	if creds[0].Type != "hash" {
		t.Errorf("expected type hash, got %q", creds[0].Type)
	}
	if creds[1].Type != "key" || creds[1].Comment != "dcsync AES-256 key" {
		t.Errorf("expected AES-256 key, got type=%q comment=%q", creds[1].Type, creds[1].Comment)
	}
	if creds[2].Type != "key" || creds[2].Comment != "dcsync AES-128 key" {
		t.Errorf("expected AES-128 key, got type=%q comment=%q", creds[2].Type, creds[2].Comment)
	}
}

func TestParseDcsyncOutput_MultipleAccounts(t *testing.T) {
	input := `[+] Administrator (RID: 500)
  Hash:   Administrator:500:aad3b435b51404ee:8846f7eaee8fb117:::
[+] krbtgt (RID: 502)
  Hash:   krbtgt:502:aad3b435b51404ee:deadbeefdeadbeef:::
  AES256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`

	creds := parseDcsyncOutput(input)
	if len(creds) != 3 {
		t.Fatalf("expected 3 credentials, got %d", len(creds))
	}
	if creds[0].Account != "Administrator" {
		t.Errorf("first credential should be Administrator, got %q", creds[0].Account)
	}
	if creds[1].Account != "krbtgt" {
		t.Errorf("second credential should be krbtgt, got %q", creds[1].Account)
	}
	if creds[2].Account != "krbtgt" {
		t.Errorf("third credential should be krbtgt, got %q", creds[2].Account)
	}
}

func TestParseDcsyncOutput_SkipsAllZerosKeys(t *testing.T) {
	input := `[+] Guest (RID: 501)
  Hash:   Guest:501:aad3b435b51404ee:31d6cfe0d16ae931:::
  AES256: 0000000000000000000000000000000000000000000000000000000000000000
  AES128: 00000000000000000000000000000000`

	creds := parseDcsyncOutput(input)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential (hash only, keys are all zeros), got %d", len(creds))
	}
	if creds[0].Type != "hash" {
		t.Errorf("expected hash type, got %q", creds[0].Type)
	}
}

func TestParseDcsyncOutput_EmptyInput(t *testing.T) {
	creds := parseDcsyncOutput("")
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials from empty input, got %d", len(creds))
	}
}

func TestParseDcsyncOutput_NoRIDLines(t *testing.T) {
	input := `Hash: some_hash_value
AES256: some_key_value`

	creds := parseDcsyncOutput(input)
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials (no account context), got %d", len(creds))
	}
}

func TestParseDcsyncOutput_EmptyHashLine(t *testing.T) {
	input := `[+] test_user (RID: 1001)
  Hash:
  AES256: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890`

	creds := parseDcsyncOutput(input)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential (AES-256 only, hash empty), got %d", len(creds))
	}
	if creds[0].Type != "key" {
		t.Errorf("expected key type, got %q", creds[0].Type)
	}
}
