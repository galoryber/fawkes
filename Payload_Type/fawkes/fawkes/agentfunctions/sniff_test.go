package agentfunctions

import (
	"testing"
)

func TestClassifySniffCredentialType_NTLM(t *testing.T) {
	if ct := classifySniffCredentialType("ntlm"); ct != "hash" {
		t.Errorf("expected hash for ntlm, got %q", ct)
	}
}

func TestClassifySniffCredentialType_NTLMv2(t *testing.T) {
	if ct := classifySniffCredentialType("ntlmv2"); ct != "hash" {
		t.Errorf("expected hash for ntlmv2, got %q", ct)
	}
}

func TestClassifySniffCredentialType_NTLMv2Relay(t *testing.T) {
	if ct := classifySniffCredentialType("ntlmv2-relay"); ct != "hash" {
		t.Errorf("expected hash for ntlmv2-relay, got %q", ct)
	}
}

func TestClassifySniffCredentialType_KerbASREP(t *testing.T) {
	if ct := classifySniffCredentialType("krb-asrep"); ct != "ticket" {
		t.Errorf("expected ticket for krb-asrep, got %q", ct)
	}
}

func TestClassifySniffCredentialType_KerbTGSREP(t *testing.T) {
	if ct := classifySniffCredentialType("krb-tgsrep"); ct != "ticket" {
		t.Errorf("expected ticket for krb-tgsrep, got %q", ct)
	}
}

func TestClassifySniffCredentialType_FTP(t *testing.T) {
	if ct := classifySniffCredentialType("ftp"); ct != "plaintext" {
		t.Errorf("expected plaintext for ftp, got %q", ct)
	}
}

func TestClassifySniffCredentialType_HTTP(t *testing.T) {
	if ct := classifySniffCredentialType("http"); ct != "plaintext" {
		t.Errorf("expected plaintext for http, got %q", ct)
	}
}

func TestFormatSniffRealm_WithPort(t *testing.T) {
	realm := formatSniffRealm("192.168.1.10", 445)
	if realm != "192.168.1.10:445" {
		t.Errorf("expected 192.168.1.10:445, got %q", realm)
	}
}

func TestFormatSniffRealm_WithoutPort(t *testing.T) {
	realm := formatSniffRealm("10.0.0.1", 0)
	if realm != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %q", realm)
	}
}

func TestFormatSniffRealm_HighPort(t *testing.T) {
	realm := formatSniffRealm("10.0.0.1", 8080)
	if realm != "10.0.0.1:8080" {
		t.Errorf("expected 10.0.0.1:8080, got %q", realm)
	}
}
