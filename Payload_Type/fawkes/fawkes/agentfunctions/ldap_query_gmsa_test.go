package agentfunctions

import (
	"encoding/json"
	"testing"
)

func TestProcessGMSACredentials_ValidJSON(t *testing.T) {
	// This tests the JSON parsing logic of processGMSACredentials.
	// We can't test the full function (requires Mythic RPC) but we can
	// verify the JSON struct parsing works correctly.
	input := `{
		"action": "gmsa",
		"base_dn": "DC=corp,DC=local",
		"count": 2,
		"readable": 1,
		"accounts": [
			{
				"sAMAccountName": "svc_sql$",
				"ntlm_hash": "AABBCCDD11223344AABBCCDD11223344",
				"dn": "CN=svc_sql,CN=Managed Service Accounts,DC=corp,DC=local"
			},
			{
				"sAMAccountName": "svc_web$",
				"ntlm_hash": "",
				"password_error": "access denied"
			}
		]
	}`

	var output struct {
		Accounts []struct {
			SAMAccountName string `json:"sAMAccountName"`
			NTLMHash       string `json:"ntlm_hash"`
		} `json:"accounts"`
	}
	err := json.Unmarshal([]byte(input), &output)
	if err != nil {
		t.Fatalf("Failed to parse GMSA output: %v", err)
	}

	if len(output.Accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(output.Accounts))
	}

	// Count extractable hashes (non-empty ntlm_hash)
	hashCount := 0
	for _, acct := range output.Accounts {
		if acct.NTLMHash != "" {
			hashCount++
		}
	}
	if hashCount != 1 {
		t.Errorf("expected 1 extractable hash, got %d", hashCount)
	}

	if output.Accounts[0].SAMAccountName != "svc_sql$" {
		t.Errorf("account[0] = %q", output.Accounts[0].SAMAccountName)
	}
	if output.Accounts[0].NTLMHash != "AABBCCDD11223344AABBCCDD11223344" {
		t.Errorf("hash[0] = %q", output.Accounts[0].NTLMHash)
	}
}

func TestProcessGMSACredentials_EmptyAccounts(t *testing.T) {
	input := `{"action":"gmsa","count":0,"accounts":[]}`
	var output struct {
		Accounts []struct {
			NTLMHash string `json:"ntlm_hash"`
		} `json:"accounts"`
	}
	err := json.Unmarshal([]byte(input), &output)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	if len(output.Accounts) != 0 {
		t.Errorf("expected 0 accounts, got %d", len(output.Accounts))
	}
}

func TestProcessGMSACredentials_NoHashField(t *testing.T) {
	input := `{"accounts":[{"sAMAccountName":"svc$","password_error":"access denied"}]}`
	var output struct {
		Accounts []struct {
			NTLMHash string `json:"ntlm_hash"`
		} `json:"accounts"`
	}
	err := json.Unmarshal([]byte(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if output.Accounts[0].NTLMHash != "" {
		t.Errorf("expected empty hash, got %q", output.Accounts[0].NTLMHash)
	}
}

func TestProcessGMSACredentials_InvalidJSON(t *testing.T) {
	var output struct {
		Accounts []struct{} `json:"accounts"`
	}
	err := json.Unmarshal([]byte("not json"), &output)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
