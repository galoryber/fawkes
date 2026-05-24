package agentfunctions

import (
	"testing"
)

func TestParseASREPHashes_ValidRoastedEntries(t *testing.T) {
	input := `[{"account":"svc_backup","etype":"23","hash":"$krb5asrep$23$svc_backup@CORP.LOCAL:abc123...","status":"roasted"},{"account":"svc_web","etype":"23","hash":"$krb5asrep$23$svc_web@CORP.LOCAL:def456...","status":"roasted"}]`

	creds := parseASREPHashes(input, "dc01.corp.local")
	if len(creds) != 2 {
		t.Fatalf("expected 2 creds, got %d", len(creds))
	}
	if creds[0].Account != "svc_backup" {
		t.Errorf("creds[0].Account = %q", creds[0].Account)
	}
	if creds[0].CredentialType != "hash" {
		t.Errorf("creds[0].CredentialType = %q, want hash", creds[0].CredentialType)
	}
	if creds[0].Realm != "dc01.corp.local" {
		t.Errorf("creds[0].Realm = %q", creds[0].Realm)
	}
	if creds[0].Comment != "asrep-roast (23)" {
		t.Errorf("creds[0].Comment = %q", creds[0].Comment)
	}
}

func TestParseASREPHashes_SkipsNonRoasted(t *testing.T) {
	input := `[{"account":"admin","etype":"23","hash":"","status":"not_vulnerable"},{"account":"svc","etype":"23","hash":"$krb5asrep$23$svc...","status":"roasted"}]`

	creds := parseASREPHashes(input, "dc01")
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred (skip non-roasted), got %d", len(creds))
	}
	if creds[0].Account != "svc" {
		t.Errorf("Account = %q, want svc", creds[0].Account)
	}
}

func TestParseASREPHashes_SkipsEmptyHash(t *testing.T) {
	input := `[{"account":"user1","etype":"23","hash":"","status":"roasted"}]`

	creds := parseASREPHashes(input, "dc01")
	if len(creds) != 0 {
		t.Errorf("expected 0 creds (empty hash), got %d", len(creds))
	}
}

func TestParseASREPHashes_InvalidJSON(t *testing.T) {
	creds := parseASREPHashes("not json", "dc01")
	if creds != nil {
		t.Errorf("expected nil for invalid JSON, got %d creds", len(creds))
	}
}

func TestParseASREPHashes_EmptyArray(t *testing.T) {
	creds := parseASREPHashes("[]", "dc01")
	if len(creds) != 0 {
		t.Errorf("expected 0 for empty array, got %d", len(creds))
	}
}

func TestParseASREPHashes_EmptyString(t *testing.T) {
	creds := parseASREPHashes("", "dc01")
	if creds != nil {
		t.Errorf("expected nil for empty string, got %d", len(creds))
	}
}

func TestParseASREPHashes_MixedStatuses(t *testing.T) {
	input := `[
		{"account":"a","etype":"17","hash":"hash1","status":"roasted"},
		{"account":"b","etype":"23","hash":"hash2","status":"error"},
		{"account":"c","etype":"18","hash":"hash3","status":"roasted"},
		{"account":"d","etype":"23","hash":"","status":"roasted"}
	]`

	creds := parseASREPHashes(input, "realm")
	if len(creds) != 2 {
		t.Fatalf("expected 2 (a roasted + c roasted), got %d", len(creds))
	}
	if creds[0].Account != "a" || creds[1].Account != "c" {
		t.Errorf("accounts = [%s, %s]", creds[0].Account, creds[1].Account)
	}
}
