package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsAuthCookie(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"_gh_sess", true},
		{"JSESSIONID", true},
		{"connect.sid", true},
		{"session_token", true},
		{"csrf_token", true},
		{"access_token", true},
		{"refresh_token", true},
		{"PHPSESSID", true},
		{"ASP.NET_SessionId", true},
		{"laravel_session", true},
		{"oauth_state", true},
		{"jwt_payload", true},
		{"_ga", false},
		{"_gid", false},
		{"NID", false},
		{"theme", false},
		{"language", false},
		{"viewed_items", false},
		{"cookie_consent", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAuthCookie(tt.name)
			if got != tt.want {
				t.Errorf("isAuthCookie(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsAuthStorageKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"access_token", true},
		{"refresh_token", true},
		{"auth_session", true},
		{"jwt_data", true},
		{"oauth_state", true},
		{"csrf_token", true},
		{"apikey", true},
		{"api_key", true},
		{"cognito_user", true},
		{"id_token", true},
		{"theme", false},
		{"sidebar_collapsed", false},
		{"last_viewed", false},
		{"cache_v2", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := isAuthStorageKey(tt.key)
			if got != tt.want {
				t.Errorf("isAuthStorageKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestFilterAuthCookies(t *testing.T) {
	cookies := []cdpCookie{
		{Name: "_gh_sess", Value: "abc123", Domain: ".github.com", HTTPOnly: true, Secure: true},
		{Name: "_ga", Value: "GA1.2.123", Domain: ".github.com"},
		{Name: "session_id", Value: "xyz789", Domain: ".example.com", Secure: true},
		{Name: "theme", Value: "dark", Domain: ".example.com"},
		{Name: "JSESSIONID", Value: "node0abc", Domain: "app.example.com", HTTPOnly: true},
	}

	auth := filterAuthCookies(cookies)
	if len(auth) != 3 {
		t.Fatalf("filterAuthCookies returned %d cookies, want 3", len(auth))
	}

	names := make(map[string]bool)
	for _, c := range auth {
		names[c.Name] = true
	}
	for _, expected := range []string{"_gh_sess", "session_id", "JSESSIONID"} {
		if !names[expected] {
			t.Errorf("expected cookie %q in auth cookies", expected)
		}
	}
}

func TestCookieFlags(t *testing.T) {
	tests := []struct {
		name   string
		cookie cdpCookie
		want   string
	}{
		{
			"all flags",
			cdpCookie{HTTPOnly: true, Secure: true, SameSite: "Lax"},
			"HttpOnly, Secure, SameSite=Lax",
		},
		{
			"httponly only",
			cdpCookie{HTTPOnly: true},
			"HttpOnly",
		},
		{
			"no flags",
			cdpCookie{},
			"none",
		},
		{
			"secure and samesite",
			cdpCookie{Secure: true, SameSite: "Strict"},
			"Secure, SameSite=Strict",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cookieFlags(tt.cookie)
			if got != tt.want {
				t.Errorf("cookieFlags() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTruncateValue(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short", "short", 10, "short"},
		{"exact", "exactly10c", 10, "exactly10c"},
		{"truncated", "this is a longer string", 15, "this is a lo..."},
		{"empty", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateValue(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateValue(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestExtractOrigin(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://github.com/dashboard", "https://github.com"},
		{"https://mail.google.com/mail/u/0/", "https://mail.google.com"},
		{"http://localhost:3000/api/data", "http://localhost:3000"},
		{"https://example.com", "https://example.com"},
		{"ftp://files.example.com/pub/readme", "ftp://files.example.com"},
		{"no-scheme", "no-scheme"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractOrigin(tt.url)
			if got != tt.want {
				t.Errorf("extractOrigin(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestReadDevToolsActivePort(t *testing.T) {
	tmpDir := t.TempDir()
	portFile := filepath.Join(tmpDir, "DevToolsActivePort")

	// Non-existent file
	if port := readDevToolsActivePort("/nonexistent/DevToolsActivePort"); port != 0 {
		t.Errorf("nonexistent = %d, want 0", port)
	}

	// Valid port
	os.WriteFile(portFile, []byte("9222\n/devtools/browser/abc123"), 0644)
	if port := readDevToolsActivePort(portFile); port != 9222 {
		t.Errorf("valid = %d, want 9222", port)
	}

	// Invalid (non-numeric)
	os.WriteFile(portFile, []byte("notanumber\n/devtools"), 0644)
	if port := readDevToolsActivePort(portFile); port != 0 {
		t.Errorf("invalid = %d, want 0", port)
	}

	// Empty
	os.WriteFile(portFile, []byte(""), 0644)
	if port := readDevToolsActivePort(portFile); port != 0 {
		t.Errorf("empty = %d, want 0", port)
	}

	// Out of range
	os.WriteFile(portFile, []byte("99999"), 0644)
	if port := readDevToolsActivePort(portFile); port != 0 {
		t.Errorf("out-of-range = %d, want 0", port)
	}

	// Zero
	os.WriteFile(portFile, []byte("0"), 0644)
	if port := readDevToolsActivePort(portFile); port != 0 {
		t.Errorf("zero = %d, want 0", port)
	}

	// Port with whitespace
	os.WriteFile(portFile, []byte("  9333  \n/devtools/browser/xyz"), 0644)
	if port := readDevToolsActivePort(portFile); port != 9333 {
		t.Errorf("whitespace = %d, want 9333", port)
	}
}

func TestCDPCookieJSON(t *testing.T) {
	raw := `{
		"name": "_gh_sess",
		"value": "abc123xyz",
		"domain": ".github.com",
		"path": "/",
		"expires": 1776182400.0,
		"size": 45,
		"httpOnly": true,
		"secure": true,
		"sameSite": "Lax",
		"session": false
	}`

	var cookie cdpCookie
	if err := json.Unmarshal([]byte(raw), &cookie); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if cookie.Name != "_gh_sess" {
		t.Errorf("Name = %q", cookie.Name)
	}
	if cookie.Domain != ".github.com" {
		t.Errorf("Domain = %q", cookie.Domain)
	}
	if !cookie.HTTPOnly {
		t.Error("HTTPOnly should be true")
	}
	if !cookie.Secure {
		t.Error("Secure should be true")
	}
	if cookie.SameSite != "Lax" {
		t.Errorf("SameSite = %q", cookie.SameSite)
	}
}

func TestCDPPageTargetJSON(t *testing.T) {
	raw := `{
		"id": "ABC123",
		"type": "page",
		"title": "GitHub Dashboard",
		"url": "https://github.com/dashboard",
		"webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/ABC123"
	}`

	var target cdpPageTarget
	if err := json.Unmarshal([]byte(raw), &target); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if target.ID != "ABC123" {
		t.Errorf("ID = %q", target.ID)
	}
	if target.Type != "page" {
		t.Errorf("Type = %q", target.Type)
	}
	if target.Title != "GitHub Dashboard" {
		t.Errorf("Title = %q", target.Title)
	}
	if target.WebSocketURL != "ws://127.0.0.1:9222/devtools/page/ABC123" {
		t.Errorf("WebSocketURL = %q", target.WebSocketURL)
	}
}

func TestCredBrowserLiveNoDebug(t *testing.T) {
	result := credBrowserLive(credHarvestArgs{Action: "browser-live"})
	if result.Status != "error" {
		t.Errorf("Status = %q, want %q", result.Status, "error")
	}
	if !result.Completed {
		t.Error("Completed should be true even on error")
	}
	if result.Credentials != nil {
		t.Error("Credentials should be nil when no browsers found")
	}
	if !strings.Contains(result.Output, "No debuggable browsers found") {
		t.Error("Output should mention no debuggable browsers found")
	}
}

func TestCDPCookieArrayJSON(t *testing.T) {
	// Test parsing the full Network.getAllCookies response structure
	raw := `{"cookies": [
		{"name": "session", "value": "s1", "domain": ".example.com", "path": "/", "expires": 0, "httpOnly": true, "secure": true, "sameSite": "Lax", "session": true},
		{"name": "pref", "value": "dark", "domain": "example.com", "path": "/", "expires": 1776182400, "httpOnly": false, "secure": false, "sameSite": "None", "session": false}
	]}`

	var result struct {
		Cookies []cdpCookie `json:"cookies"`
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(result.Cookies) != 2 {
		t.Fatalf("got %d cookies, want 2", len(result.Cookies))
	}

	auth := filterAuthCookies(result.Cookies)
	if len(auth) != 1 {
		t.Errorf("got %d auth cookies, want 1", len(auth))
	}
	if len(auth) > 0 && auth[0].Name != "session" {
		t.Errorf("auth cookie name = %q, want %q", auth[0].Name, "session")
	}
}
