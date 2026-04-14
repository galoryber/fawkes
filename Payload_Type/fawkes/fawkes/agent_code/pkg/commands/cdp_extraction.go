package commands

import (
	"encoding/json"
	"fmt"
	"strings"
)

// --- Cookie extraction ---

type cdpCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"`
	Size     int     `json:"size"`
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	SameSite string  `json:"sameSite"`
	Session  bool    `json:"session"`
}

// cdpGetAllCookies extracts all cookies via CDP Network.getAllCookies.
func cdpGetAllCookies(wsURL string) ([]cdpCookie, error) {
	client, err := newCDPClient(wsURL)
	if err != nil {
		return nil, err
	}
	defer client.close()

	result, err := client.send("Network.getAllCookies", nil)
	if err != nil {
		return nil, err
	}

	var cookieResult struct {
		Cookies []cdpCookie `json:"cookies"`
	}
	if err := json.Unmarshal(result, &cookieResult); err != nil {
		return nil, fmt.Errorf("parse cookies: %w", err)
	}

	return cookieResult.Cookies, nil
}

// authCookieNames are cookie names commonly associated with authentication sessions.
var authCookieNames = []string{
	"session", "sess", "sid", "token", "auth", "jwt", "access_token",
	"refresh_token", "id_token", "csrf", "xsrf", "_gh_sess", "connect.sid",
	"saml", "sso", "oidc", "oauth", "bearer", "api_key", "apikey",
	"phpsessid", "jsessionid", "asp.net_sessionid", "laravel_session",
	"wordpress_logged_in", "wp-settings", "__stripe", "cognito",
}

// filterAuthCookies returns cookies whose names match common auth patterns.
func filterAuthCookies(cookies []cdpCookie) []cdpCookie {
	var auth []cdpCookie
	for _, c := range cookies {
		if isAuthCookie(c.Name) {
			auth = append(auth, c)
		}
	}
	return auth
}

// isAuthCookie checks if a cookie name matches auth-related patterns.
func isAuthCookie(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range authCookieNames {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func cookieFlags(c cdpCookie) string {
	var flags []string
	if c.HTTPOnly {
		flags = append(flags, "HttpOnly")
	}
	if c.Secure {
		flags = append(flags, "Secure")
	}
	if c.SameSite != "" {
		flags = append(flags, "SameSite="+c.SameSite)
	}
	if len(flags) == 0 {
		return "none"
	}
	return strings.Join(flags, ", ")
}

// --- Storage extraction ---

// cdpGetStorage extracts localStorage and sessionStorage from a page via Runtime.evaluate.
func cdpGetStorage(wsURL string) (local map[string]string, session map[string]string, err error) {
	client, err := newCDPClient(wsURL)
	if err != nil {
		return nil, nil, err
	}
	defer client.close()

	local = cdpEvalStorage(client, "localStorage")
	session = cdpEvalStorage(client, "sessionStorage")

	return local, session, nil
}

// cdpEvalStorage evaluates a JavaScript expression to extract storage entries.
func cdpEvalStorage(client *cdpClient, storageType string) map[string]string {
	expr := fmt.Sprintf(`(function() {
		try {
			var s = window.%s;
			if (!s || s.length === 0) return "{}";
			var obj = {};
			for (var i = 0; i < s.length; i++) {
				var k = s.key(i);
				var v = s.getItem(k);
				if (v && v.length < 4096) obj[k] = v;
			}
			return JSON.stringify(obj);
		} catch(e) { return "{}"; }
	})()`, storageType)

	result, err := client.send("Runtime.evaluate", map[string]interface{}{
		"expression":    expr,
		"returnByValue": true,
	})
	if err != nil {
		return nil
	}

	var evalResult struct {
		Result struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result, &evalResult); err != nil {
		return nil
	}

	entries := make(map[string]string)
	json.Unmarshal([]byte(evalResult.Result.Value), &entries)
	return entries
}

// authStorageKeyPatterns are patterns for localStorage/sessionStorage keys that likely contain auth data.
var authStorageKeyPatterns = []string{
	"token", "auth", "session", "jwt", "access", "refresh", "bearer",
	"api_key", "apikey", "credential", "secret", "oauth", "oidc",
	"saml", "sso", "csrf", "xsrf", "id_token", "cognito",
}

// isAuthStorageKey checks if a storage key matches auth-related patterns.
func isAuthStorageKey(key string) bool {
	lower := strings.ToLower(key)
	for _, pattern := range authStorageKeyPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
