package commands

import (
	"encoding/json"
	"testing"
)

func TestRemovePKCS7Padding(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"empty", []byte{}, ""},
		{"single pad byte", []byte("hello\x03\x03\x03"), "hello"},
		{"full block pad", []byte{0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08}, ""},
		{"one byte pad", []byte("testing\x01"), "testing"},
		{"no valid padding", []byte("abcdefgh"), "abcdefgh"},
		{"password-check format", []byte("password-check\x02\x02"), "password-check"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := removePKCS7Padding(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(result) != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestFirefoxLoginsJSONParsing(t *testing.T) {
	loginsJSON := `{
		"logins": [
			{
				"hostname": "https://example.com",
				"encryptedUsername": "dGVzdA==",
				"encryptedPassword": "cGFzcw=="
			},
			{
				"hostname": "https://bank.example.com",
				"encryptedUsername": "",
				"encryptedPassword": ""
			}
		]
	}`

	var logins firefoxLoginsJSON
	if err := json.Unmarshal([]byte(loginsJSON), &logins); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(logins.Logins) != 2 {
		t.Fatalf("expected 2 logins, got %d", len(logins.Logins))
	}
	if logins.Logins[0].Hostname != "https://example.com" {
		t.Errorf("hostname mismatch: %s", logins.Logins[0].Hostname)
	}
	if logins.Logins[0].EncryptedUsername != "dGVzdA==" {
		t.Errorf("username mismatch: %s", logins.Logins[0].EncryptedUsername)
	}
	if logins.Logins[1].EncryptedUsername != "" {
		t.Errorf("expected empty username for second entry")
	}
}

func TestSHA1Hash(t *testing.T) {
	result := sha1Hash([]byte("test"))
	if len(result) != 20 {
		t.Errorf("SHA1 hash should be 20 bytes, got %d", len(result))
	}
}

func TestHMACSHA1(t *testing.T) {
	result := hmacSHA1([]byte("key"), []byte("data"))
	if len(result) != 20 {
		t.Errorf("HMAC-SHA1 should be 20 bytes, got %d", len(result))
	}
}

func TestFirefoxLoginEntryFields(t *testing.T) {
	entry := firefoxLoginEntry{
		Browser:  "Firefox",
		URL:      "https://example.com",
		Username: "user@example.com",
		Password: "secret123",
	}
	if entry.Browser != "Firefox" {
		t.Error("Browser mismatch")
	}
	if entry.URL != "https://example.com" {
		t.Error("URL mismatch")
	}
}
