package commands

import (
	"testing"
)

func TestParseDomainUser(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantDomain string
		wantUser   string
	}{
		{"backslash format", `CORP\jsmith`, "CORP", "jsmith"},
		{"UPN format", "jsmith@corp.local", "corp.local", "jsmith"},
		{"plain username", "jsmith", "", "jsmith"},
		{"empty string", "", "", ""},
		{"backslash with dot domain", `.\localuser`, ".", "localuser"},
		{"UPN with subdomain", "admin@sub.corp.local", "sub.corp.local", "admin"},
		{"backslash takes priority", `DOMAIN\user@extra`, "DOMAIN", "user@extra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, user := parseDomainUser(tt.input)
			if domain != tt.wantDomain {
				t.Errorf("domain = %q, want %q", domain, tt.wantDomain)
			}
			if user != tt.wantUser {
				t.Errorf("user = %q, want %q", user, tt.wantUser)
			}
		})
	}
}

func TestStripLMPrefix(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			"LM:NT format",
			"aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
			"31d6cfe0d16ae931b73c59d7e0c089c0",
		},
		{
			"NT hash only",
			"31d6cfe0d16ae931b73c59d7e0c089c0",
			"31d6cfe0d16ae931b73c59d7e0c089c0",
		},
		{
			"with whitespace",
			"  aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0  ",
			"31d6cfe0d16ae931b73c59d7e0c089c0",
		},
		{
			"empty string",
			"",
			"",
		},
		{
			"short colon-separated",
			"abc:def",
			"abc:def",
		},
		{
			"wrong lengths",
			"aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
			"aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripLMPrefix(tt.input)
			if got != tt.want {
				t.Errorf("stripLMPrefix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestZeroCredentials(t *testing.T) {
	// Use heap-allocated strings (string concatenation forces allocation)
	// ZeroString uses unsafe.StringData to clear underlying bytes, which
	// crashes on read-only string literals.
	password := string([]byte("s3cretP@ss!"))
	hash := string([]byte("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"))
	keyData := string([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBA..."))

	zeroCredentials(&password, &hash, &keyData)

	if password != "" {
		t.Errorf("password not zeroed: %q", password)
	}
	if hash != "" {
		t.Errorf("hash not zeroed: %q", hash)
	}
	if keyData != "" {
		t.Errorf("keyData not zeroed: %q", keyData)
	}
}

func TestZeroCredentialsSingle(t *testing.T) {
	field := string([]byte("sensitive"))
	zeroCredentials(&field)
	if field != "" {
		t.Errorf("field not zeroed: %q", field)
	}
}

func TestZeroCredentialsEmpty(t *testing.T) {
	// Should not panic with no args
	zeroCredentials()
}
