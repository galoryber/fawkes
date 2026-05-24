package agentfunctions

import (
	"strings"
	"testing"
)

func TestParseAWSAccessKeys_Valid(t *testing.T) {
	input := `[+] AWS IAM Role: ec2-admin
AccessKeyId: AKIAIOSFODNN7EXAMPLE
SecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

	c := parseAWSAccessKeys(input)
	if c == nil {
		t.Fatal("expected credential")
	}
	if !strings.Contains(c.Account, "ec2-admin") {
		t.Errorf("expected role in account, got %q", c.Account)
	}
	if !strings.Contains(c.Credential, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("expected access key in credential, got %q", c.Credential)
	}
	if c.CredType != "key" {
		t.Errorf("expected key type, got %q", c.CredType)
	}
}

func TestParseAWSAccessKeys_NoRole(t *testing.T) {
	input := `AccessKeyId: AKIAIOSFODNN7EXAMPLE
SecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

	c := parseAWSAccessKeys(input)
	if c == nil {
		t.Fatal("expected credential")
	}
	if c.Account != "AWS IAM" {
		t.Errorf("expected 'AWS IAM' without role, got %q", c.Account)
	}
}

func TestParseAWSAccessKeys_MissingSecret(t *testing.T) {
	input := "AccessKeyId: AKIAIOSFODNN7EXAMPLE"
	c := parseAWSAccessKeys(input)
	if c != nil {
		t.Error("expected nil for missing secret key")
	}
}

func TestParseAWSAccessKeys_Empty(t *testing.T) {
	c := parseAWSAccessKeys("")
	if c != nil {
		t.Error("expected nil for empty input")
	}
}

func TestDetectCloudProvider_Azure(t *testing.T) {
	if p := detectCloudProvider("Azure Managed Identity token: ..."); p != "Azure" {
		t.Errorf("expected Azure, got %q", p)
	}
}

func TestDetectCloudProvider_GCP(t *testing.T) {
	if p := detectCloudProvider("GCP metadata response"); p != "GCP" {
		t.Errorf("expected GCP, got %q", p)
	}
}

func TestDetectCloudProvider_Google(t *testing.T) {
	if p := detectCloudProvider("google compute engine metadata"); p != "GCP" {
		t.Errorf("expected GCP for 'google', got %q", p)
	}
}

func TestDetectCloudProvider_Default(t *testing.T) {
	if p := detectCloudProvider("some metadata response"); p != "Cloud" {
		t.Errorf("expected Cloud, got %q", p)
	}
}

func TestParseCloudToken_AzureToken(t *testing.T) {
	input := `Azure Managed Identity
access_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imk2bEdrM0`

	c := parseCloudToken(input)
	if c == nil {
		t.Fatal("expected credential")
	}
	if !strings.Contains(c.Account, "Azure") {
		t.Errorf("expected Azure in account, got %q", c.Account)
	}
	if c.CredType != "token" {
		t.Errorf("expected token type, got %q", c.CredType)
	}
}

func TestParseCloudToken_ShortToken(t *testing.T) {
	input := "access_token: short"
	c := parseCloudToken(input)
	if c != nil {
		t.Error("expected nil for short token")
	}
}

func TestParseCloudToken_NoToken(t *testing.T) {
	c := parseCloudToken("no token here")
	if c != nil {
		t.Error("expected nil for no token")
	}
}

func TestParsePersistCredential_AWS(t *testing.T) {
	input := `SUCCESS: Created AWS access key
Account: backdoor-user
AccessKey: AKIA1234567890EXAMPL
SecretKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

	c := parsePersistCredential(input)
	if c == nil {
		t.Fatal("expected credential")
	}
	if !strings.Contains(c.Account, "AWS Persist") {
		t.Errorf("expected 'AWS Persist' in account, got %q", c.Account)
	}
	if !strings.Contains(c.Account, "backdoor-user") {
		t.Errorf("expected backdoor-user in account, got %q", c.Account)
	}
}

func TestParsePersistCredential_Azure(t *testing.T) {
	input := `SUCCESS: Created Azure service principal
App ID: 12345678-1234-1234-1234-123456789012
Secret: abc123def456
Account: malicious-app`

	c := parsePersistCredential(input)
	if c == nil {
		t.Fatal("expected credential")
	}
	if !strings.Contains(c.Account, "Azure") {
		t.Errorf("expected Azure provider, got %q", c.Account)
	}
}

func TestParsePersistCredential_MissingKey(t *testing.T) {
	input := "SUCCESS: Created\nAccount: test"
	c := parsePersistCredential(input)
	if c != nil {
		t.Error("expected nil for missing key/secret")
	}
}
