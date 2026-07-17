package commands

import (
	"testing"
)

func TestIsAuthCookie_MatchesKnownPatterns(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"session_id", true},
		{"PHPSESSID", true},
		{"JSESSIONID", true},
		{"access_token", true},
		{"refresh_token", true},
		{"csrf_token", true},
		{"__stripe_mid", true},
		{"auth_key", true},
		{"jwt_payload", true},
		{"_gh_sess", true},
		{"connect.sid", true},
		{"oauth_state", true},
		{"bearer_token", true},
		{"api_key_v2", true},
		{"wordpress_logged_in_abc", true},
		{"saml_response", true},
		{"cognito_id", true},
	}
	for _, tc := range cases {
		if got := isAuthCookie(tc.name); got != tc.want {
			t.Errorf("isAuthCookie(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsAuthCookie_RejectsNonAuth(t *testing.T) {
	cases := []string{
		"_ga",
		"_gid",
		"NID",
		"consent",
		"theme",
		"language",
		"tracking_id",
		"ab_test_group",
		"cookie_notice_accepted",
	}
	for _, name := range cases {
		if isAuthCookie(name) {
			t.Errorf("isAuthCookie(%q) = true, want false", name)
		}
	}
}

func TestIsAuthCookie_CaseInsensitive(t *testing.T) {
	cases := []string{"SESSION_ID", "Access_Token", "JWT", "CSRF_TOKEN"}
	for _, name := range cases {
		if !isAuthCookie(name) {
			t.Errorf("isAuthCookie(%q) = false, want true (case insensitive)", name)
		}
	}
}

func TestCDPFilterAuthCookies(t *testing.T) {
	cookies := []cdpCookie{
		{Name: "session_id", Value: "abc123", Domain: ".example.com"},
		{Name: "_ga", Value: "GA1.2.xyz", Domain: ".example.com"},
		{Name: "csrf_token", Value: "def456", Domain: ".example.com"},
		{Name: "theme", Value: "dark", Domain: ".example.com"},
		{Name: "jwt", Value: "eyJ...", Domain: ".api.example.com"},
	}

	result := filterAuthCookies(cookies)
	if len(result) != 3 {
		t.Fatalf("filterAuthCookies returned %d cookies, want 3", len(result))
	}

	names := map[string]bool{}
	for _, c := range result {
		names[c.Name] = true
	}
	for _, expected := range []string{"session_id", "csrf_token", "jwt"} {
		if !names[expected] {
			t.Errorf("filterAuthCookies missing expected cookie %q", expected)
		}
	}
}

func TestCDPFilterAuthCookies_EmptyInput(t *testing.T) {
	result := filterAuthCookies(nil)
	if result != nil {
		t.Errorf("filterAuthCookies(nil) = %v, want nil", result)
	}
}

func TestCDPFilterAuthCookies_NoMatches(t *testing.T) {
	cookies := []cdpCookie{
		{Name: "_ga", Value: "GA1.2.xyz"},
		{Name: "theme", Value: "dark"},
	}
	result := filterAuthCookies(cookies)
	if result != nil {
		t.Errorf("filterAuthCookies with no auth cookies = %v, want nil", result)
	}
}

func TestCookieFlags_AllSet(t *testing.T) {
	c := cdpCookie{HTTPOnly: true, Secure: true, SameSite: "Strict"}
	got := cookieFlags(c)
	if got != "HttpOnly, Secure, SameSite=Strict" {
		t.Errorf("cookieFlags = %q, want %q", got, "HttpOnly, Secure, SameSite=Strict")
	}
}

func TestCookieFlags_NoneSet(t *testing.T) {
	c := cdpCookie{}
	got := cookieFlags(c)
	if got != "none" {
		t.Errorf("cookieFlags = %q, want %q", got, "none")
	}
}

func TestCookieFlags_OnlyHttpOnly(t *testing.T) {
	c := cdpCookie{HTTPOnly: true}
	got := cookieFlags(c)
	if got != "HttpOnly" {
		t.Errorf("cookieFlags = %q, want %q", got, "HttpOnly")
	}
}

func TestCookieFlags_SecureAndSameSite(t *testing.T) {
	c := cdpCookie{Secure: true, SameSite: "Lax"}
	got := cookieFlags(c)
	if got != "Secure, SameSite=Lax" {
		t.Errorf("cookieFlags = %q, want %q", got, "Secure, SameSite=Lax")
	}
}

func TestIsAuthStorageKey_MatchesPatterns(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"access_token", true},
		{"user_session", true},
		{"jwt_data", true},
		{"auth_state", true},
		{"csrf_nonce", true},
		{"api_key", true},
		{"oauth_redirect", true},
		{"oidc_config", true},
		{"bearer_token", true},
		{"cognito_user_pool", true},
		{"id_token_claims", true},
		{"refresh_token_exp", true},
		{"xsrf_protection", true},
		{"saml_assertion", true},
		{"sso_ticket", true},
		{"credential_cache", true},
		{"secret_key_base", true},
	}
	for _, tc := range cases {
		if got := isAuthStorageKey(tc.key); got != tc.want {
			t.Errorf("isAuthStorageKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

func TestIsAuthStorageKey_RejectsNonAuth(t *testing.T) {
	cases := []string{
		"page_count",
		"last_visited",
		"ui_preferences",
		"cart_items",
		"dark_mode",
		"language",
	}
	for _, key := range cases {
		if isAuthStorageKey(key) {
			t.Errorf("isAuthStorageKey(%q) = true, want false", key)
		}
	}
}
