package commands

import (
	"encoding/json"
	"testing"
	"unicode/utf16"
)

func TestUtf16LEToUTF8_Simple(t *testing.T) {
	input := "hello world"
	data := testUTF8ToUTF16LE(input)
	result, err := utf16LEToUTF8(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != input {
		t.Errorf("got %q, want %q", result, input)
	}
}

func TestUtf16LEToUTF8_WithBOM(t *testing.T) {
	runes := []rune("test")
	u16 := utf16.Encode(runes)
	data := make([]byte, 2+len(u16)*2)
	data[0] = 0xFF // BOM
	data[1] = 0xFE
	for i, v := range u16 {
		data[2+2*i] = byte(v)
		data[2+2*i+1] = byte(v >> 8)
	}

	result, err := utf16LEToUTF8(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "test" {
		t.Errorf("got %q, want %q", result, "test")
	}
}

func TestUtf16LEToUTF8_TooShort(t *testing.T) {
	_, err := utf16LEToUTF8([]byte{0x00})
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestUtf16LEToUTF8_Unicode(t *testing.T) {
	input := "résumé 日本語"
	data := testUTF8ToUTF16LE(input)
	result, err := utf16LEToUTF8(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != input {
		t.Errorf("got %q, want %q", result, input)
	}
}

func TestUtf16LEToUTF8_TrailingNulls(t *testing.T) {
	// Simulate Windows fixed-size buffer with trailing null characters
	input := "hello"
	data := testUTF8ToUTF16LE(input)
	// Append 6 null bytes (3 null uint16 values)
	data = append(data, 0, 0, 0, 0, 0, 0)

	result, err := utf16LEToUTF8(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != input {
		t.Errorf("got %q (len %d), want %q (len %d)", result, len(result), input, len(input))
	}
}

func TestUtf16LEToUTF8_TrailingNullsJSON(t *testing.T) {
	// Simulate a .tbres file with trailing nulls after JSON content
	jsonStr := `{"key":"value"}`
	data := testUTF8ToUTF16LE(jsonStr)
	data = append(data, 0, 0, 0, 0) // trailing nulls

	result, err := utf16LEToUTF8(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the result is valid JSON
	var parsed map[string]string
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("result should be valid JSON, got error: %v (raw: %q)", err, result)
	}
	if parsed["key"] != "value" {
		t.Errorf("parsed[key] = %q", parsed["key"])
	}
}

func TestMatchAuthCookie_KnownPatterns(t *testing.T) {
	tests := []struct {
		host     string
		name     string
		wantDesc string
	}{
		{"login.microsoftonline.com", "ESTSAUTH", "Entra ID session (persistent)"},
		{"login.microsoftonline.com", "ESTSAUTHPERSISTENT", "Entra ID persistent session"},
		{".teams.microsoft.com", "authtoken", "Teams auth token"},
		{".teams.microsoft.com", "skypetoken_asm", "Teams Skype token"},
		{".office.com", "OIDCAuthCookie", "Office OIDC auth"},
		{".sharepoint.com", "FedAuth", "SharePoint federated auth"},
		{".sharepoint.com", "rtFa", "SharePoint refresh token"},
		{"login.live.com", "ESTSAUTH", "Microsoft Live session"},
		{"substrate.office.com", "SubstrateAuth", "Substrate auth"},
	}

	for _, tt := range tests {
		t.Run(tt.host+"/"+tt.name, func(t *testing.T) {
			got := matchAuthCookie(tt.host, tt.name)
			if got != tt.wantDesc {
				t.Errorf("matchAuthCookie(%q, %q) = %q, want %q", tt.host, tt.name, got, tt.wantDesc)
			}
		})
	}
}

func TestMatchAuthCookie_GenericNames(t *testing.T) {
	tests := []struct {
		host string
		name string
		want bool
	}{
		{"example.com", "access_token", true},
		{"example.com", "session_id", true},
		{"example.com", "jwt_data", true},
		{"example.com", "auth_cookie", true},
		{"example.com", "refresh_token_v2", true},
		{"example.com", "sso_state", true},
		// Non-matching
		{"example.com", "theme", false},
		{"example.com", "language", false},
		{"google.com", "NID", false},
		{"example.com", "_ga", false},
	}

	for _, tt := range tests {
		t.Run(tt.host+"/"+tt.name, func(t *testing.T) {
			got := matchAuthCookie(tt.host, tt.name)
			if (got != "") != tt.want {
				t.Errorf("matchAuthCookie(%q, %q) = %q, wantMatch=%v", tt.host, tt.name, got, tt.want)
			}
		})
	}
}

func TestParseTokenResponseJSON_Structured(t *testing.T) {
	input := `{
		"TokenResponses": [{
			"Token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
			"TokenType": "Bearer",
			"Resource": "https://graph.microsoft.com",
			"ClientId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
			"RefreshToken": "0.ARwA2Q_refresh_token_value"
		}]
	}`

	tokens, err := parseTokenResponseJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}

	tok := tokens[0]
	if tok.resource != "https://graph.microsoft.com" {
		t.Errorf("resource = %q", tok.resource)
	}
	if tok.clientID != "d3590ed6-52b3-4102-aeff-aad2292ab01c" {
		t.Errorf("clientID = %q", tok.clientID)
	}
	if tok.tokenType != "Bearer" {
		t.Errorf("tokenType = %q", tok.tokenType)
	}
	if len(tok.token) < 7 || tok.token[:7] != "eyJhbGc" {
		t.Errorf("token should start with JWT header, got %q", tok.token)
	}
	if tok.refreshToken == "" {
		t.Error("expected refresh token")
	}
}

func TestParseTokenResponseJSON_MultipleTokens(t *testing.T) {
	input := `{
		"TokenResponses": [
			{"Token": "token1", "TokenType": "Bearer", "Resource": "https://graph.microsoft.com", "ClientId": "client1"},
			{"Token": "token2", "TokenType": "Bearer", "Resource": "https://outlook.office.com", "ClientId": "client2"},
			{"Token": "", "TokenType": "Bearer"}
		]
	}`

	tokens, err := parseTokenResponseJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens (empty token skipped), got %d", len(tokens))
	}
}

func TestParseTokenResponseJSON_Flat(t *testing.T) {
	input := `{
		"access_token": "eyJhbGciOiJSUzI1NiJ9.flat_payload.sig",
		"token_type": "Bearer",
		"resource": "https://outlook.office.com",
		"client_id": "test-client-id",
		"refresh_token": "flat_refresh_value"
	}`

	tokens, err := parseTokenResponseJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}

	tok := tokens[0]
	if tok.resource != "https://outlook.office.com" {
		t.Errorf("resource = %q", tok.resource)
	}
	if tok.tokenType != "Bearer" {
		t.Errorf("tokenType = %q", tok.tokenType)
	}
	if tok.refreshToken != "flat_refresh_value" {
		t.Errorf("refreshToken = %q", tok.refreshToken)
	}
}

func TestParseTokenResponseJSON_EmbeddedJWT(t *testing.T) {
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature_here"
	input := "some garbage before " + jwt + " and after"

	tokens, err := parseTokenResponseJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if tokens[0].tokenType != "JWT" {
		t.Errorf("tokenType = %q, want JWT", tokens[0].tokenType)
	}
	if tokens[0].token != jwt {
		t.Errorf("extracted JWT doesn't match")
	}
}

func TestParseTokenResponseJSON_NoTokens(t *testing.T) {
	input := `{"irrelevant": "data", "no_tokens": true}`
	tokens, err := parseTokenResponseJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(tokens))
	}
}

func TestParseTokenResponseJSON_ShortJWT(t *testing.T) {
	input := "eyJ.short.jwt"
	tokens, err := parseTokenResponseJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens for short JWT, got %d", len(tokens))
	}
}

func TestTbresObjectParsing_AccountStore(t *testing.T) {
	obj := map[string]interface{}{
		"TBDataStoreObject": map[string]interface{}{
			"Header": map[string]interface{}{
				"ObjectType": "AccountStore",
			},
		},
	}
	data, _ := json.Marshal(obj)

	var parsed tbresObject
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if parsed.TBDataStoreObject.Header.ObjectType != "AccountStore" {
		t.Errorf("ObjectType = %q", parsed.TBDataStoreObject.Header.ObjectType)
	}
}

func TestTbresObjectParsing_TokenResponse(t *testing.T) {
	obj := map[string]interface{}{
		"TBDataStoreObject": map[string]interface{}{
			"Header": map[string]interface{}{
				"ObjectType": "TokenResponse",
			},
			"ObjectData": map[string]interface{}{
				"SystemDefinedProperties": map[string]interface{}{
					"ResponseBytes": map[string]interface{}{
						"Type":        "InlineBytes",
						"IsProtected": true,
						"Value":       "dGVzdA==",
					},
					"Expiration": map[string]interface{}{
						"Type":        "InlineBytes",
						"IsProtected": false,
						"Value":       "AAAA",
					},
				},
			},
		},
	}
	data, _ := json.Marshal(obj)

	var parsed tbresObject
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	rb, ok := parsed.TBDataStoreObject.ObjectData.SystemDefinedProperties["ResponseBytes"]
	if !ok {
		t.Fatal("ResponseBytes not found")
	}
	if !rb.IsProtected {
		t.Error("expected IsProtected=true")
	}
	if rb.Value != "dGVzdA==" {
		t.Errorf("Value = %q", rb.Value)
	}
}

// testUTF8ToUTF16LE converts a UTF-8 string to UTF-16LE bytes for testing
func testUTF8ToUTF16LE(s string) []byte {
	runes := []rune(s)
	u16 := utf16.Encode(runes)
	data := make([]byte, len(u16)*2)
	for i, v := range u16 {
		data[2*i] = byte(v)
		data[2*i+1] = byte(v >> 8)
	}
	return data
}
