package commands

import (
	"strings"
	"testing"
)

// --- ticketKrbErrorMsg tests ---

func TestTicketKrbErrorMsgKnownCodes(t *testing.T) {
	tests := []struct {
		code     int32
		contains string
	}{
		{6, "KDC_ERR_C_PRINCIPAL_UNKNOWN"},
		{12, "KDC_ERR_POLICY"},
		{13, "KDC_ERR_BADOPTION"},
		{15, "KDC_ERR_SUMTYPE_NOSUPP"},
		{18, "KDC_ERR_CLIENT_REVOKED"},
		{23, "KDC_ERR_KEY_EXPIRED"},
		{24, "KDC_ERR_PREAUTH_FAILED"},
		{25, "KDC_ERR_PREAUTH_REQUIRED"},
		{31, "KRB_AP_ERR_SKEW"},
		{41, "KRB_AP_ERR_BAD_INTEGRITY"},
		{68, "KDC_ERR_WRONG_REALM"},
	}

	for _, tc := range tests {
		result := ticketKrbErrorMsg(tc.code)
		if len(result) == 0 {
			t.Errorf("code %d: expected non-empty message", tc.code)
		}
		if !strings.Contains(result, tc.contains) {
			t.Errorf("code %d: expected message containing '%s', got '%s'", tc.code, tc.contains, result)
		}
	}
}

func TestTicketKrbErrorMsgUnknown(t *testing.T) {
	result := ticketKrbErrorMsg(999)
	if !strings.Contains(result, "999") {
		t.Errorf("expected message containing code number, got '%s'", result)
	}
}

func TestTicketKrbErrorMsgZero(t *testing.T) {
	result := ticketKrbErrorMsg(0)
	if len(result) == 0 {
		t.Error("expected non-empty message for code 0")
	}
}

// --- ticketParseKeyType tests ---

func TestTicketParseKeyTypeAES256Valid(t *testing.T) {
	key := make([]byte, 32)
	etypeID, cfgName, errResult := ticketParseKeyType("aes256", key)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Output)
	}
	if etypeID != 18 {
		t.Errorf("expected etypeID 18, got %d", etypeID)
	}
	if cfgName != "aes256-cts-hmac-sha1-96" {
		t.Errorf("expected cfgName 'aes256-cts-hmac-sha1-96', got '%s'", cfgName)
	}
}

func TestTicketParseKeyTypeAES256WrongSize(t *testing.T) {
	key := make([]byte, 16) // wrong size
	_, _, errResult := ticketParseKeyType("aes256", key)
	if errResult == nil {
		t.Fatal("expected error for wrong key size")
		return
	}
	if errResult.Status != "error" {
		t.Errorf("expected status 'error', got '%s'", errResult.Status)
	}
}

func TestTicketParseKeyTypeAES128Valid(t *testing.T) {
	key := make([]byte, 16)
	etypeID, cfgName, errResult := ticketParseKeyType("aes128", key)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Output)
	}
	if etypeID != 17 {
		t.Errorf("expected etypeID 17, got %d", etypeID)
	}
	if cfgName != "aes128-cts-hmac-sha1-96" {
		t.Errorf("expected cfgName 'aes128-cts-hmac-sha1-96', got '%s'", cfgName)
	}
}

func TestTicketParseKeyTypeAES128WrongSize(t *testing.T) {
	key := make([]byte, 32) // wrong size
	_, _, errResult := ticketParseKeyType("aes128", key)
	if errResult == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestTicketParseKeyTypeRC4Valid(t *testing.T) {
	key := make([]byte, 16)
	etypeID, cfgName, errResult := ticketParseKeyType("rc4", key)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Output)
	}
	if etypeID != 23 {
		t.Errorf("expected etypeID 23, got %d", etypeID)
	}
	if cfgName != "rc4-hmac" {
		t.Errorf("expected cfgName 'rc4-hmac', got '%s'", cfgName)
	}
}

func TestTicketParseKeyTypeNTLMAlias(t *testing.T) {
	key := make([]byte, 16)
	etypeID, _, errResult := ticketParseKeyType("ntlm", key)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Output)
	}
	if etypeID != 23 {
		t.Errorf("expected etypeID 23 for NTLM alias, got %d", etypeID)
	}
}

func TestTicketParseKeyTypeRC4WrongSize(t *testing.T) {
	key := make([]byte, 32)
	_, _, errResult := ticketParseKeyType("rc4", key)
	if errResult == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestTicketParseKeyTypeUnknown(t *testing.T) {
	_, _, errResult := ticketParseKeyType("des", make([]byte, 8))
	if errResult == nil {
		t.Fatal("expected error for unknown key type")
		return
	}
	if !strings.Contains(errResult.Output, "des") {
		t.Errorf("error should mention the unknown type, got '%s'", errResult.Output)
	}
}

func TestTicketParseKeyTypeCaseInsensitive(t *testing.T) {
	key := make([]byte, 32)
	etypeID, _, errResult := ticketParseKeyType("AES256", key)
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Output)
	}
	if etypeID != 18 {
		t.Errorf("expected etypeID 18 for uppercase 'AES256', got %d", etypeID)
	}
}
