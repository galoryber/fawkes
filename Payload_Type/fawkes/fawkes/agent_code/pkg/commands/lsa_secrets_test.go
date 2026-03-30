//go:build windows

package commands

import (
	"encoding/json"
	"testing"
)

func TestLsaSecretsCommandName(t *testing.T) {
	assertCommandName(t, &LsaSecretsCommand{}, "lsa-secrets")
}

func TestLsaSecretsCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &LsaSecretsCommand{})
}

func TestLsaSecretsEmptyParams(t *testing.T) {
	cmd := &LsaSecretsCommand{}
	// Empty params should default to "dump" action but will fail on privilege check
	result := cmd.Execute(mockTask("lsa-secrets", ""))
	// Expected to error without SYSTEM privileges
	if result.Status != "error" {
		// If it somehow succeeds, that's also fine
		if result.Status != "success" {
			t.Errorf("unexpected status: %q", result.Status)
		}
	}
}

func TestLsaSecretsInvalidJSON(t *testing.T) {
	cmd := &LsaSecretsCommand{}
	result := cmd.Execute(mockTask("lsa-secrets", "{invalid"))
	assertError(t, result)
}

func TestLsaSecretsArgsUnmarshal(t *testing.T) {
	var args lsaSecretsArgs
	data := `{"action":"cached"}`
	if err := json.Unmarshal([]byte(data), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.Action != "cached" {
		t.Errorf("expected action=cached, got %q", args.Action)
	}
}

func TestLsaSecretsDefaultAction(t *testing.T) {
	var args lsaSecretsArgs
	json.Unmarshal([]byte(`{}`), &args)
	// Default should be empty, which Execute maps to "dump"
	if args.Action != "" {
		t.Errorf("expected empty default, got %q", args.Action)
	}
}

func TestLsaSecretsDumpAction(t *testing.T) {
	cmd := &LsaSecretsCommand{}
	params, _ := json.Marshal(lsaSecretsArgs{Action: "dump"})
	result := cmd.Execute(mockTask("lsa-secrets", string(params)))
	// Will fail without SYSTEM — that's expected
	assertError(t, result)
	assertOutputContains(t, result, "boot key")
}

func TestLsaSecretsCachedAction(t *testing.T) {
	cmd := &LsaSecretsCommand{}
	params, _ := json.Marshal(lsaSecretsArgs{Action: "cached"})
	result := cmd.Execute(mockTask("lsa-secrets", string(params)))
	// Will fail without SYSTEM — that's expected
	assertError(t, result)
	assertOutputContains(t, result, "boot key")
}
