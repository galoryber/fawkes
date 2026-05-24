package agentfunctions

import (
	"testing"
)

// --- parseShadowHashes tests ---

func TestParseShadowHashes_ValidOutput(t *testing.T) {
	input := `=== Password Hashes ===
root:$6$abc123$longhashedvalue:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
setup:$6$def456$anotherhash:19000:0:99999:7:::`

	creds := parseShadowHashes(input)
	if len(creds) != 2 {
		t.Fatalf("expected 2 shadow hashes (daemon has * not $), got %d", len(creds))
	}
	if creds[0].Account != "root" {
		t.Errorf("expected root, got %q", creds[0].Account)
	}
	if creds[0].Type != "hash" {
		t.Errorf("expected hash type, got %q", creds[0].Type)
	}
	if creds[0].Source != "shadow" {
		t.Errorf("expected shadow source, got %q", creds[0].Source)
	}
	if creds[1].Account != "setup" {
		t.Errorf("expected setup, got %q", creds[1].Account)
	}
}

func TestParseShadowHashes_EtcShadowHeader(t *testing.T) {
	input := `--- /etc/shadow ---
testuser:$y$j9T$hash:19000:0:99999:7:::`

	creds := parseShadowHashes(input)
	if len(creds) != 1 {
		t.Fatalf("expected 1 hash, got %d", len(creds))
	}
	if creds[0].Account != "testuser" {
		t.Errorf("expected testuser, got %q", creds[0].Account)
	}
}

func TestParseShadowHashes_NoShadowHeader(t *testing.T) {
	input := `Some random output
root:$6$abc:19000:0:99999:7:::`

	creds := parseShadowHashes(input)
	if len(creds) != 0 {
		t.Errorf("expected 0 hashes (no shadow header), got %d", len(creds))
	}
}

func TestParseShadowHashes_EmptyUsername(t *testing.T) {
	input := `Password Hashes
:$6$abc:19000:0:99999:7:::`

	creds := parseShadowHashes(input)
	if len(creds) != 0 {
		t.Errorf("expected 0 hashes (empty username), got %d", len(creds))
	}
}

// --- parseEnvVarCredentials tests ---

func TestParseEnvVarCredentials_ValidSection(t *testing.T) {
	input := `=== Sensitive Environment Variables ===
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_PASSWORD=supersecret
===`

	creds := parseEnvVarCredentials(input)
	if len(creds) != 2 {
		t.Fatalf("expected 2 env var credentials, got %d", len(creds))
	}
	if creds[0].Account != "AWS_SECRET_ACCESS_KEY" {
		t.Errorf("expected AWS_SECRET_ACCESS_KEY, got %q", creds[0].Account)
	}
	if creds[0].Type != "plaintext" {
		t.Errorf("expected plaintext type, got %q", creds[0].Type)
	}
	if creds[0].Source != "env" {
		t.Errorf("expected env source, got %q", creds[0].Source)
	}
	if creds[1].Account != "DATABASE_PASSWORD" {
		t.Errorf("expected DATABASE_PASSWORD, got %q", creds[1].Account)
	}
	if creds[1].Value != "supersecret" {
		t.Errorf("expected supersecret, got %q", creds[1].Value)
	}
}

func TestParseEnvVarCredentials_EmptyValue(t *testing.T) {
	input := `=== Sensitive Environment Variables ===
EMPTY_VAR=
HAS_VALUE=test
===`

	creds := parseEnvVarCredentials(input)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential (empty value skipped), got %d", len(creds))
	}
	if creds[0].Account != "HAS_VALUE" {
		t.Errorf("expected HAS_VALUE, got %q", creds[0].Account)
	}
}

func TestParseEnvVarCredentials_NoSection(t *testing.T) {
	creds := parseEnvVarCredentials("Some random output without env section")
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(creds))
	}
}

func TestParseEnvVarCredentials_ValueWithEquals(t *testing.T) {
	input := `=== Sensitive Environment Variables ===
CONNECTION_STRING=host=db;password=secret
===`

	creds := parseEnvVarCredentials(input)
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].Value != "host=db;password=secret" {
		t.Errorf("expected full value with equals, got %q", creds[0].Value)
	}
}
