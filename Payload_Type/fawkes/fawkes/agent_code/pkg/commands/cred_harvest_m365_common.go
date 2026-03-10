package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf16"
)

// tbresObject represents the JSON structure inside a .tbres file
type tbresObject struct {
	TBDataStoreObject struct {
		Header struct {
			ObjectType string `json:"ObjectType"`
		} `json:"Header"`
		ObjectData struct {
			SystemDefinedProperties map[string]tbresProperty `json:"SystemDefinedProperties"`
		} `json:"ObjectData"`
	} `json:"TBDataStoreObject"`
}

type tbresProperty struct {
	Type        string `json:"Type"`
	IsProtected bool   `json:"IsProtected"`
	Value       string `json:"Value"`
}

// tokenResponse represents the decrypted token data inside ResponseBytes
type tokenResponse struct {
	TokenResponses []struct {
		Token        string `json:"Token"`
		TokenType    string `json:"TokenType"`
		Resource     string `json:"Resource"`
		Authority    string `json:"Authority"`
		ClientID     string `json:"ClientId"`
		Scope        string `json:"Scope"`
		ExpiresOn    string `json:"ExpiresOn"`
		RefreshToken string `json:"RefreshToken"`
	} `json:"TokenResponses"`
}

type extractedToken struct {
	resource     string
	clientID     string
	tokenType    string
	token        string
	refreshToken string
}

// authCookiePatterns lists cookie names and host patterns that contain OAuth/auth tokens
var authCookiePatterns = []struct {
	hostPattern string
	cookieName  string
	description string
}{
	{"login.microsoftonline.com", "ESTSAUTH", "Entra ID session (persistent)"},
	{"login.microsoftonline.com", "ESTSAUTHPERSISTENT", "Entra ID persistent session"},
	{"login.microsoftonline.com", "ESTSAUTHLIGHT", "Entra ID light session"},
	{"login.microsoftonline.com", "SignInStateCookie", "Sign-in state"},
	{"login.live.com", "ESTSAUTH", "Microsoft Live session"},
	{"login.live.com", "ESTSAUTHPERSISTENT", "Microsoft Live persistent session"},
	{".microsoft.com", "MSISAuth", "Microsoft IS auth"},
	{".teams.microsoft.com", "authtoken", "Teams auth token"},
	{".teams.microsoft.com", "skypetoken_asm", "Teams Skype token"},
	{".teams.microsoft.com", "SSODATA", "Teams SSO data"},
	{".office.com", "OIDCAuthCookie", "Office OIDC auth"},
	{".office.com", "SignInStateCookie", "Office sign-in state"},
	{".sharepoint.com", "FedAuth", "SharePoint federated auth"},
	{".sharepoint.com", "rtFa", "SharePoint refresh token"},
	{"substrate.office.com", "SubstrateAuth", "Substrate auth"},
	{"outlook.office.com", "ClientId", "Outlook client ID"},
	{"outlook.office365.com", "ClientId", "Outlook 365 client ID"},
}

// utf16LEToUTF8 converts a byte slice from UTF-16LE (with optional BOM) to a UTF-8 string
func utf16LEToUTF8(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("data too short")
	}

	// Strip BOM if present
	if data[0] == 0xFF && data[1] == 0xFE {
		data = data[2:]
	}

	if len(data)%2 != 0 {
		data = data[:len(data)-1] // trim trailing byte if odd
	}

	u16s := make([]uint16, len(data)/2)
	for i := range u16s {
		u16s[i] = uint16(data[2*i]) | uint16(data[2*i+1])<<8
	}

	runes := utf16.Decode(u16s)
	return string(runes), nil
}

// parseTokenResponseJSON tries to extract tokens from decrypted ResponseBytes.
// The format varies — sometimes it's structured JSON, sometimes raw token data.
func parseTokenResponseJSON(data []byte) ([]extractedToken, error) {
	// Try structured TokenResponse format first
	var resp tokenResponse
	if err := json.Unmarshal(data, &resp); err == nil && len(resp.TokenResponses) > 0 {
		var tokens []extractedToken
		for _, tr := range resp.TokenResponses {
			if tr.Token == "" {
				continue
			}
			tokens = append(tokens, extractedToken{
				resource:     tr.Resource,
				clientID:     tr.ClientID,
				tokenType:    tr.TokenType,
				token:        tr.Token,
				refreshToken: tr.RefreshToken,
			})
		}
		return tokens, nil
	}

	// Try as a flat JSON object with common token field names
	var flat map[string]interface{}
	if err := json.Unmarshal(data, &flat); err == nil {
		var tokens []extractedToken
		token := extractedToken{}

		for _, key := range []string{"access_token", "AccessToken", "Token"} {
			if v, ok := flat[key].(string); ok && v != "" {
				token.token = v
				break
			}
		}
		for _, key := range []string{"refresh_token", "RefreshToken"} {
			if v, ok := flat[key].(string); ok && v != "" {
				token.refreshToken = v
				break
			}
		}
		for _, key := range []string{"resource", "Resource", "aud"} {
			if v, ok := flat[key].(string); ok && v != "" {
				token.resource = v
				break
			}
		}
		for _, key := range []string{"client_id", "ClientId", "ClientID"} {
			if v, ok := flat[key].(string); ok && v != "" {
				token.clientID = v
				break
			}
		}
		for _, key := range []string{"token_type", "TokenType"} {
			if v, ok := flat[key].(string); ok && v != "" {
				token.tokenType = v
				break
			}
		}

		if token.token != "" {
			tokens = append(tokens, token)
		}
		if len(tokens) > 0 {
			return tokens, nil
		}
	}

	// Check if the raw data contains a JWT (eyJ...) — some responses embed tokens directly
	s := string(data)
	if idx := strings.Index(s, "eyJ"); idx >= 0 {
		// Find the JWT boundary (JWTs are base64url with dots)
		end := idx
		for end < len(s) && (s[end] == '.' || s[end] == '-' || s[end] == '_' ||
			(s[end] >= 'a' && s[end] <= 'z') || (s[end] >= 'A' && s[end] <= 'Z') ||
			(s[end] >= '0' && s[end] <= '9')) {
			end++
		}
		jwt := s[idx:end]
		// Valid JWTs have at least 2 dots (header.payload.signature)
		if strings.Count(jwt, ".") >= 2 && len(jwt) > 50 {
			return []extractedToken{{
				token:     jwt,
				tokenType: "JWT",
			}}, nil
		}
	}

	return nil, nil
}

// matchAuthCookie checks if a cookie matches any known auth token pattern
func matchAuthCookie(host, name string) string {
	hostLower := strings.ToLower(host)
	for _, p := range authCookiePatterns {
		if strings.Contains(hostLower, strings.ToLower(p.hostPattern)) && strings.EqualFold(name, p.cookieName) {
			return p.description
		}
	}

	// Generic detection: cookie names containing token-related terms
	nameLower := strings.ToLower(name)
	tokenNames := []string{"token", "auth", "session", "jwt", "bearer", "access", "refresh", "sso"}
	for _, t := range tokenNames {
		if strings.Contains(nameLower, t) {
			return "auth cookie"
		}
	}

	return ""
}
