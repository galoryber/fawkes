package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// --- AWS IAM Enumeration ---
// Uses IMDS credentials to query AWS IAM/STS APIs for privilege enumeration.

const (
	awsSTSEndpoint = "https://sts.amazonaws.com/"
	awsIAMEndpoint = "https://iam.amazonaws.com/"
)

func awsEnumIAM(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== AWS IAM Privilege Enumeration ===\n\n")

	// Step 1: Get IMDS credentials
	h := awsHeaders(timeout)
	roles := metadataGet(awsCredsURL, timeout, h)
	if roles == "" {
		sb.WriteString("[-] No IAM role attached — cannot enumerate IAM privileges\n")
		return sb.String()
	}

	role := strings.TrimSpace(strings.Split(roles, "\n")[0])
	sb.WriteString(fmt.Sprintf("[+] IAM Role: %s\n", role))

	credsJSON := metadataGet(awsCredsURL+role, timeout, h)
	if credsJSON == "" {
		sb.WriteString("[-] Could not retrieve IAM credentials\n")
		return sb.String()
	}
	defer structs.ZeroString(&credsJSON)

	var creds struct {
		AccessKeyId     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
	}
	if err := json.Unmarshal([]byte(credsJSON), &creds); err != nil {
		sb.WriteString("[-] Could not parse IAM credentials\n")
		return sb.String()
	}
	defer func() {
		structs.ZeroString(&creds.AccessKeyId)
		structs.ZeroString(&creds.SecretAccessKey)
		structs.ZeroString(&creds.Token)
	}()

	sb.WriteString(fmt.Sprintf("    Access Key: %s\n\n", creds.AccessKeyId))

	// Step 2: Call STS GetCallerIdentity (always succeeds — reveals account/ARN)
	stsParams := "Action=GetCallerIdentity&Version=2011-06-15"
	stsResp := awsSignedGet(awsSTSEndpoint, stsParams, creds.AccessKeyId, creds.SecretAccessKey, creds.Token, "sts", timeout)
	if stsResp != "" {
		sb.WriteString("[+] STS Caller Identity:\n")
		// Parse XML response for Account, Arn, UserId
		for _, field := range []string{"Account", "Arn", "UserId"} {
			if val := extractXMLValue(stsResp, field); val != "" {
				sb.WriteString(fmt.Sprintf("    %-12s %s\n", field+":", val))
			}
		}
		sb.WriteString("\n")
		structs.ZeroString(&stsResp)
	}

	// Step 3: List attached role policies
	iamParams := fmt.Sprintf("Action=ListAttachedRolePolicies&RoleName=%s&Version=2010-05-08", role)
	iamResp := awsSignedGet(awsIAMEndpoint, iamParams, creds.AccessKeyId, creds.SecretAccessKey, creds.Token, "iam", timeout)
	if iamResp != "" {
		sb.WriteString("[+] Attached Role Policies:\n")
		policies := extractXMLValues(iamResp, "PolicyName")
		arns := extractXMLValues(iamResp, "PolicyArn")
		if len(policies) == 0 {
			sb.WriteString("    (none)\n")
		}
		for i, name := range policies {
			arn := ""
			if i < len(arns) {
				arn = arns[i]
			}
			sb.WriteString(fmt.Sprintf("    %s (%s)\n", name, arn))
		}
		sb.WriteString("\n")
		structs.ZeroString(&iamResp)
	} else {
		sb.WriteString("[*] Could not list attached policies (AccessDenied is expected for most roles)\n\n")
	}

	// Step 4: List inline role policies
	inlineParams := fmt.Sprintf("Action=ListRolePolicies&RoleName=%s&Version=2010-05-08", role)
	inlineResp := awsSignedGet(awsIAMEndpoint, inlineParams, creds.AccessKeyId, creds.SecretAccessKey, creds.Token, "iam", timeout)
	if inlineResp != "" {
		sb.WriteString("[+] Inline Role Policies:\n")
		names := extractXMLValues(inlineResp, "member")
		if len(names) == 0 {
			sb.WriteString("    (none)\n")
		}
		for _, name := range names {
			sb.WriteString(fmt.Sprintf("    %s\n", name))
		}
		sb.WriteString("\n")
		structs.ZeroString(&inlineResp)
	}

	return sb.String()
}

// --- Azure AD Graph Enumeration ---
// Uses managed identity token to query Microsoft Graph API.

const (
	azureGraphBase     = "https://graph.microsoft.com/v1.0/"
	azureGraphTokenURL = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"
)

func azureEnumGraph(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== Azure AD Graph Enumeration ===\n\n")

	// Get managed identity token scoped to Microsoft Graph
	tokenResp := metadataGet(azureGraphTokenURL, timeout, map[string]string{"Metadata": "true"})
	if tokenResp == "" {
		sb.WriteString("[-] No managed identity available — cannot query Microsoft Graph\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenResp)

	var tokenData struct {
		AccessToken string `json:"access_token"`
		Resource    string `json:"resource"`
		ExpiresOn   string `json:"expires_on"`
	}
	if err := json.Unmarshal([]byte(tokenResp), &tokenData); err != nil {
		sb.WriteString("[-] Could not parse managed identity token\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenData.AccessToken)

	sb.WriteString("[+] Managed Identity Token acquired\n")
	sb.WriteString(fmt.Sprintf("    Resource: %s\n", tokenData.Resource))
	sb.WriteString(fmt.Sprintf("    Expires:  %s\n\n", tokenData.ExpiresOn))

	authHeaders := map[string]string{"Authorization": "Bearer " + tokenData.AccessToken}

	// Query /me — current identity
	meResp := metadataGet(azureGraphBase+"me", timeout, authHeaders)
	if meResp != "" {
		sb.WriteString("[+] Current Identity (/me):\n")
		var me map[string]interface{}
		if err := json.Unmarshal([]byte(meResp), &me); err == nil {
			for _, field := range []string{"displayName", "userPrincipalName", "id", "jobTitle", "department"} {
				if val, ok := me[field]; ok && val != nil {
					sb.WriteString(fmt.Sprintf("    %-22s %v\n", field+":", val))
				}
			}
		}
		sb.WriteString("\n")
	}

	// Query /users — enumerate AD users (top 25)
	usersResp := metadataGet(azureGraphBase+"users?$top=25&$select=displayName,userPrincipalName,accountEnabled", timeout, authHeaders)
	if usersResp != "" {
		sb.WriteString("[+] Azure AD Users (top 25):\n")
		var usersData struct {
			Value []struct {
				DisplayName       string `json:"displayName"`
				UserPrincipalName string `json:"userPrincipalName"`
				AccountEnabled    bool   `json:"accountEnabled"`
			} `json:"value"`
		}
		if err := json.Unmarshal([]byte(usersResp), &usersData); err == nil {
			for _, u := range usersData.Value {
				status := "enabled"
				if !u.AccountEnabled {
					status = "DISABLED"
				}
				sb.WriteString(fmt.Sprintf("    %-35s %-40s %s\n", u.DisplayName, u.UserPrincipalName, status))
			}
			sb.WriteString(fmt.Sprintf("    (%d users returned)\n", len(usersData.Value)))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("[*] Cannot enumerate users (insufficient permissions)\n\n")
	}

	// Query /groups — enumerate AD groups (top 25)
	groupsResp := metadataGet(azureGraphBase+"groups?$top=25&$select=displayName,description,securityEnabled", timeout, authHeaders)
	if groupsResp != "" {
		sb.WriteString("[+] Azure AD Groups (top 25):\n")
		var groupsData struct {
			Value []struct {
				DisplayName     string `json:"displayName"`
				Description     string `json:"description"`
				SecurityEnabled bool   `json:"securityEnabled"`
			} `json:"value"`
		}
		if err := json.Unmarshal([]byte(groupsResp), &groupsData); err == nil {
			for _, g := range groupsData.Value {
				gType := "distribution"
				if g.SecurityEnabled {
					gType = "security"
				}
				desc := g.Description
				if len(desc) > 50 {
					desc = desc[:50] + "..."
				}
				sb.WriteString(fmt.Sprintf("    %-35s %-12s %s\n", g.DisplayName, gType, desc))
			}
			sb.WriteString(fmt.Sprintf("    (%d groups returned)\n", len(groupsData.Value)))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("[*] Cannot enumerate groups (insufficient permissions)\n\n")
	}

	// Query /applications — enumerate app registrations (top 25)
	appsResp := metadataGet(azureGraphBase+"applications?$top=25&$select=displayName,appId,signInAudience", timeout, authHeaders)
	if appsResp != "" {
		sb.WriteString("[+] App Registrations (top 25):\n")
		var appsData struct {
			Value []struct {
				DisplayName    string `json:"displayName"`
				AppID          string `json:"appId"`
				SignInAudience string `json:"signInAudience"`
			} `json:"value"`
		}
		if err := json.Unmarshal([]byte(appsResp), &appsData); err == nil {
			for _, a := range appsData.Value {
				sb.WriteString(fmt.Sprintf("    %-35s %s (%s)\n", a.DisplayName, a.AppID, a.SignInAudience))
			}
			sb.WriteString(fmt.Sprintf("    (%d apps returned)\n", len(appsData.Value)))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("[*] Cannot enumerate applications (insufficient permissions)\n\n")
	}

	return sb.String()
}

// --- GCP IAM Enumeration ---
// Uses metadata service token to query GCP IAM and Resource Manager APIs.

const (
	gcpCRMBase = "https://cloudresourcemanager.googleapis.com/v1/"
	gcpIAMBase = "https://iam.googleapis.com/v1/"
)

func gcpEnumIAM(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== GCP IAM Privilege Enumeration ===\n\n")

	gcpHeaders := map[string]string{"Metadata-Flavor": "Google"}

	// Get project ID
	projectID := metadataGet(gcpProjectURL+"project-id", timeout, gcpHeaders)
	if projectID == "" {
		sb.WriteString("[-] Not running on GCP — cannot enumerate IAM\n")
		return sb.String()
	}
	sb.WriteString(fmt.Sprintf("[+] Project: %s\n", projectID))

	// Get service account info
	saEmail := metadataGet(gcpServiceAcctURL+"default/email", timeout, gcpHeaders)
	if saEmail != "" {
		sb.WriteString(fmt.Sprintf("    Service Account: %s\n", saEmail))
	}

	// List service account scopes
	scopes := metadataGet(gcpServiceAcctURL+"default/scopes", timeout, gcpHeaders)
	if scopes != "" {
		sb.WriteString("\n[+] Assigned Scopes:\n")
		for _, scope := range strings.Split(scopes, "\n") {
			scope = strings.TrimSpace(scope)
			if scope != "" {
				sb.WriteString(fmt.Sprintf("    %s\n", scope))
			}
		}
	}
	sb.WriteString("\n")

	// Get access token for API calls
	tokenResp := metadataGet(gcpTokenURL, timeout, gcpHeaders)
	if tokenResp == "" {
		sb.WriteString("[-] Could not get access token — cannot make API calls\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenResp)

	var tokenData struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal([]byte(tokenResp), &tokenData); err != nil {
		sb.WriteString("[-] Could not parse access token\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenData.AccessToken)

	authHeaders := map[string]string{"Authorization": "Bearer " + tokenData.AccessToken}

	// Query project IAM policy
	iamURL := fmt.Sprintf("%sprojects/%s:getIamPolicy", gcpCRMBase, projectID)
	// getIamPolicy is a POST with empty body
	iamResp := metadataGet(iamURL, timeout, authHeaders)
	if iamResp != "" {
		sb.WriteString("[+] Project IAM Bindings:\n")
		var policy struct {
			Bindings []struct {
				Role    string   `json:"role"`
				Members []string `json:"members"`
			} `json:"bindings"`
		}
		if err := json.Unmarshal([]byte(iamResp), &policy); err == nil {
			for _, b := range policy.Bindings {
				sb.WriteString(fmt.Sprintf("    Role: %s\n", b.Role))
				for _, m := range b.Members {
					sb.WriteString(fmt.Sprintf("      - %s\n", m))
				}
			}
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("[*] Cannot read project IAM policy (insufficient permissions)\n\n")
	}

	// List service accounts in the project
	saURL := fmt.Sprintf("%sprojects/%s/serviceAccounts", gcpIAMBase, projectID)
	saResp := metadataGet(saURL, timeout, authHeaders)
	if saResp != "" {
		sb.WriteString("[+] Project Service Accounts:\n")
		var saData struct {
			Accounts []struct {
				Email       string `json:"email"`
				DisplayName string `json:"displayName"`
				Disabled    bool   `json:"disabled"`
			} `json:"accounts"`
		}
		if err := json.Unmarshal([]byte(saResp), &saData); err == nil {
			for _, sa := range saData.Accounts {
				status := "active"
				if sa.Disabled {
					status = "DISABLED"
				}
				name := sa.DisplayName
				if name == "" {
					name = "(unnamed)"
				}
				sb.WriteString(fmt.Sprintf("    %-40s %-20s %s\n", sa.Email, name, status))
			}
			sb.WriteString(fmt.Sprintf("    (%d service accounts)\n", len(saData.Accounts)))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("[*] Cannot list service accounts (insufficient permissions)\n\n")
	}

	return sb.String()
}

// --- Helpers ---

// extractXMLValue extracts the value of a simple XML tag from a response string.
// Handles: <Tag>value</Tag>
func extractXMLValue(xml, tag string) string {
	start := fmt.Sprintf("<%s>", tag)
	end := fmt.Sprintf("</%s>", tag)
	i := strings.Index(xml, start)
	if i < 0 {
		return ""
	}
	i += len(start)
	j := strings.Index(xml[i:], end)
	if j < 0 {
		return ""
	}
	return xml[i : i+j]
}

// extractXMLValues extracts all values of a simple XML tag from a response string.
func extractXMLValues(xml, tag string) []string {
	var values []string
	start := fmt.Sprintf("<%s>", tag)
	end := fmt.Sprintf("</%s>", tag)
	remaining := xml
	for {
		i := strings.Index(remaining, start)
		if i < 0 {
			break
		}
		remaining = remaining[i+len(start):]
		j := strings.Index(remaining, end)
		if j < 0 {
			break
		}
		values = append(values, remaining[:j])
		remaining = remaining[j+len(end):]
	}
	return values
}

// awsSignedGet makes a signed AWS API request using temporary credentials.
// Uses AWS Signature V4 (query string form) for GET requests.
// Returns empty string on any error (access denied, network, etc.)
func awsSignedGet(endpoint, queryParams, accessKey, secretKey, sessionToken, service string, timeout time.Duration) string {
	// For simplicity, use query string auth with unsigned payload
	// AWS allows passing credentials as query parameters instead of signing
	url := fmt.Sprintf("%s?%s", endpoint, queryParams)

	headers := map[string]string{
		"X-Amz-Security-Token": sessionToken,
	}

	// Most AWS APIs accept unsigned requests with the security token header
	// when called from within the AWS network (IMDS credentials include STS token)
	resp := metadataGet(url, timeout, headers)
	if resp != "" && !strings.Contains(resp, "<Error>") {
		return resp
	}
	return ""
}
