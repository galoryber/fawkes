package agentfunctions

import (
	"testing"
)

func TestParseLSACachedCredentials_ValidOutput(t *testing.T) {
	input := `=== Cached Domain Credentials ===
[+] CORP\administrator
  $DCC2$10240#administrator#a1b2c3d4e5f6a7b8c9d0e1f2
[+] CORP\jsmith
  $DCC2$10240#jsmith#deadbeefdeadbeefdeadbeef`

	creds := parseLSACachedCredentials(input)
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}
	if creds[0].Account != "administrator" {
		t.Errorf("expected administrator, got %q", creds[0].Account)
	}
	if creds[0].Realm != "CORP" {
		t.Errorf("expected CORP realm, got %q", creds[0].Realm)
	}
	if creds[0].CredType != "hash" {
		t.Errorf("expected hash type, got %q", creds[0].CredType)
	}
	if creds[1].Account != "jsmith" {
		t.Errorf("expected jsmith, got %q", creds[1].Account)
	}
}

func TestParseLSACachedCredentials_NoDomain(t *testing.T) {
	input := `=== Cached Domain Credentials ===
[+] localuser
  nothash`

	creds := parseLSACachedCredentials(input)
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials (no backslash in identity), got %d", len(creds))
	}
}

func TestParseLSACachedCredentials_EmptyHash(t *testing.T) {
	input := `=== Cached Domain Credentials ===
[+] CORP\administrator
`

	creds := parseLSACachedCredentials(input)
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials (empty hash line), got %d", len(creds))
	}
}

func TestParseLSACachedCredentials_EmptyInput(t *testing.T) {
	creds := parseLSACachedCredentials("")
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(creds))
	}
}

func TestClassifyLSASecret_ServiceAccount(t *testing.T) {
	credType, comment, include := classifyLSASecret("_SC_MySQLService")
	if !include {
		t.Fatal("expected include=true for _SC_ prefix")
	}
	if credType != "plaintext" {
		t.Errorf("expected plaintext, got %q", credType)
	}
	if comment != "lsa-secrets (service account)" {
		t.Errorf("unexpected comment: %q", comment)
	}
}

func TestClassifyLSASecret_DefaultPassword(t *testing.T) {
	credType, _, include := classifyLSASecret("DefaultPassword")
	if !include {
		t.Fatal("expected include=true for DefaultPassword")
	}
	if credType != "plaintext" {
		t.Errorf("expected plaintext, got %q", credType)
	}
}

func TestClassifyLSASecret_DPAPISystem(t *testing.T) {
	credType, _, include := classifyLSASecret("DPAPI_SYSTEM")
	if !include {
		t.Fatal("expected include=true for DPAPI_SYSTEM")
	}
	if credType != "key" {
		t.Errorf("expected key, got %q", credType)
	}
}

func TestClassifyLSASecret_UnknownSecret(t *testing.T) {
	_, _, include := classifyLSASecret("NL$KM")
	if include {
		t.Error("expected include=false for unknown secret type")
	}
}

func TestParseLSADumpSecrets_MixedSecrets(t *testing.T) {
	input := `=== LSA Secrets ===
[+] _SC_MySQLService:
  P@ssw0rd123
[+] DefaultPassword:
  AutoLogonPass!
[+] DPAPI_SYSTEM:
  01000000d08c9ddf0115d1118c7a00c04fc297eb
[+] NL$KM:
  irrelevant_data`

	creds := parseLSADumpSecrets(input)
	if len(creds) != 3 {
		t.Fatalf("expected 3 credentials (NL$KM excluded), got %d", len(creds))
	}
	if creds[0].Account != "MySQLService" {
		t.Errorf("expected MySQLService (stripped _SC_), got %q", creds[0].Account)
	}
	if creds[0].Value != "P@ssw0rd123" {
		t.Errorf("expected P@ssw0rd123, got %q", creds[0].Value)
	}
	if creds[1].Account != "DefaultPassword" {
		t.Errorf("expected DefaultPassword, got %q", creds[1].Account)
	}
	if creds[2].Account != "DPAPI_SYSTEM" {
		t.Errorf("expected DPAPI_SYSTEM, got %q", creds[2].Account)
	}
	if creds[2].CredType != "key" {
		t.Errorf("expected key type for DPAPI, got %q", creds[2].CredType)
	}
}

func TestParseLSADumpSecrets_MultilineValue(t *testing.T) {
	input := `=== LSA Secrets ===
[+] DPAPI_SYSTEM:
  user_key: 0123456789abcdef
  machine_key: fedcba9876543210`

	creds := parseLSADumpSecrets(input)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Value != "user_key: 0123456789abcdef\nmachine_key: fedcba9876543210" {
		t.Errorf("expected multiline value, got %q", creds[0].Value)
	}
}

func TestParseLSADumpSecrets_EmptyValue(t *testing.T) {
	input := `=== LSA Secrets ===
[+] _SC_EmptyService:
[+] DefaultPassword:
  realpass`

	creds := parseLSADumpSecrets(input)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential (empty service skipped), got %d", len(creds))
	}
	if creds[0].Account != "DefaultPassword" {
		t.Errorf("expected DefaultPassword, got %q", creds[0].Account)
	}
}

func TestParseLSADumpSecrets_NoColonInHeader(t *testing.T) {
	input := `=== LSA Secrets ===
[+] NotASecret
  some_value`

	creds := parseLSADumpSecrets(input)
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials (no colon), got %d", len(creds))
	}
}
