package commands

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- normalizeProvider tests ---

func TestNormalizeProvider(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"aws lowercase", "aws", "aws"},
		{"aws uppercase", "AWS", "aws"},
		{"azure", "azure", "azure"},
		{"Azure mixed", "Azure", "azure"},
		{"gcp", "gcp", "gcp"},
		{"GCP upper", "GCP", "gcp"},
		{"digitalocean", "digitalocean", "digitalocean"},
		{"DigitalOcean mixed", "DigitalOcean", "digitalocean"},
		{"invalid provider", "alibaba", ""},
		{"empty string", "", ""},
		{"partial match", "aw", ""},
		{"spaces", " aws ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeProvider(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeProvider(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// --- Additional metadataGet edge case tests ---

func TestMetadataGet_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Write([]byte("slow"))
	}))
	defer server.Close()

	result := metadataGet(server.URL, 50*time.Millisecond, nil)
	if result != "" {
		t.Errorf("metadataGet() with timeout = %q, want empty", result)
	}
}

func TestMetadataGet_500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	result := metadataGet(server.URL, 3*time.Second, nil)
	if result != "" {
		t.Errorf("metadataGet() for 500 = %q, want empty", result)
	}
}

func TestMetadataGet_BodyLimit(t *testing.T) {
	bigBody := strings.Repeat("A", 128*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bigBody))
	}))
	defer server.Close()

	result := metadataGet(server.URL, 3*time.Second, nil)
	if len(result) > metadataMaxSize {
		t.Errorf("metadataGet() body = %d bytes, expected <= %d", len(result), metadataMaxSize)
	}
}

func TestMetadataGet_MultipleHeaders(t *testing.T) {
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	headers := map[string]string{
		"X-First":  "one",
		"X-Second": "two",
		"X-Third":  "three",
	}
	metadataGet(server.URL, 3*time.Second, headers)
	for k, v := range headers {
		if receivedHeaders.Get(k) != v {
			t.Errorf("header %s = %q, want %q", k, receivedHeaders.Get(k), v)
		}
	}
}

// --- Additional metadataPut edge case tests ---

func TestMetadataPut_403Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer server.Close()

	result := metadataPut(server.URL, 3*time.Second, nil)
	if result != "" {
		t.Errorf("metadataPut() for 403 = %q, want empty", result)
	}
}

func TestMetadataPut_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Write([]byte("slow"))
	}))
	defer server.Close()

	result := metadataPut(server.URL, 50*time.Millisecond, nil)
	if result != "" {
		t.Errorf("metadataPut() with timeout = %q, want empty", result)
	}
}

// --- Cloud constant validation tests ---

func TestCloudURLConstants(t *testing.T) {
	tests := []struct {
		name string
		url  string
		base string
	}{
		{"AWS metadata base", awsMetadataBase, "http://169.254.169.254"},
		{"AWS token URL", awsTokenURL, "http://169.254.169.254"},
		{"AWS meta URL", awsMetaURL, "http://169.254.169.254"},
		{"AWS creds URL", awsCredsURL, "http://169.254.169.254"},
		{"AWS identity URL", awsIdentityURL, "http://169.254.169.254"},
		{"AWS userdata URL", awsUserdataURL, "http://169.254.169.254"},
		{"Azure metadata base", azureMetadataBase, "http://169.254.169.254"},
		{"Azure instance URL", azureInstanceURL, "http://169.254.169.254"},
		{"Azure token URL", azureTokenURL, "http://169.254.169.254"},
		{"GCP metadata base", gcpMetadataBase, "http://metadata.google.internal"},
		{"GCP project URL", gcpProjectURL, "http://metadata.google.internal"},
		{"GCP instance URL", gcpInstanceURL, "http://metadata.google.internal"},
		{"GCP token URL", gcpTokenURL, "http://metadata.google.internal"},
		{"GCP service acct URL", gcpServiceAcctURL, "http://metadata.google.internal"},
		{"DO metadata base", doMetadataBase, "http://169.254.169.254"},
		{"DO metadata URL", doMetadataURL, "http://169.254.169.254"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.HasPrefix(tt.url, tt.base) {
				t.Errorf("%s = %q, does not start with %q", tt.name, tt.url, tt.base)
			}
		})
	}
}

func TestCloudURLPaths(t *testing.T) {
	if !strings.Contains(awsTokenURL, "/latest/api/token") {
		t.Error("AWS token URL missing /latest/api/token")
	}
	if !strings.Contains(awsMetaURL, "/latest/meta-data/") {
		t.Error("AWS meta URL missing /latest/meta-data/")
	}
	if !strings.Contains(azureInstanceURL, "api-version=") {
		t.Error("Azure instance URL missing api-version parameter")
	}
	if !strings.Contains(gcpProjectURL, "/computeMetadata/v1/project/") {
		t.Error("GCP project URL missing /computeMetadata/v1/project/")
	}
	if !strings.Contains(doMetadataURL, "/metadata/v1.json") {
		t.Error("DO metadata URL missing /metadata/v1.json")
	}
}

func TestDefaultCloudTimeout(t *testing.T) {
	if defaultCloudTimeout != 3 {
		t.Errorf("defaultCloudTimeout = %d, want 3", defaultCloudTimeout)
	}
}

func TestMetadataMaxSize(t *testing.T) {
	if metadataMaxSize != 64*1024 {
		t.Errorf("metadataMaxSize = %d, want %d", metadataMaxSize, 64*1024)
	}
}

// --- formatAWSCredsJSON tests ---

func TestFormatAWSCredsJSON_FullCredentials(t *testing.T) {
	jsonStr := `{
		"AccessKeyId": "ASIATESTACCESSKEY",
		"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"Token": "FwoGZXIvYXdzEBYaDFKfoobarTokenValueHere1234567890abcdef",
		"Expiration": "2025-06-15T12:00:00Z"
	}`
	result := formatAWSCredsJSON(jsonStr)
	if !strings.Contains(result, "ASIATESTACCESSKEY") {
		t.Error("missing AccessKeyId")
	}
	if !strings.Contains(result, "wJalrXUtnFEMI") {
		t.Error("missing SecretAccessKey")
	}
	if !strings.Contains(result, "Token:") {
		t.Error("missing Token field")
	}
	if !strings.Contains(result, "2025-06-15T12:00:00Z") {
		t.Error("missing Expiration")
	}
}

func TestFormatAWSCredsJSON_PartialFields(t *testing.T) {
	jsonStr := `{"AccessKeyId": "AKIAEXAMPLE"}`
	result := formatAWSCredsJSON(jsonStr)
	if !strings.Contains(result, "AKIAEXAMPLE") {
		t.Error("missing AccessKeyId")
	}
	if strings.Contains(result, "SecretAccessKey:") {
		t.Error("should not have SecretAccessKey when not in JSON")
	}
}

func TestFormatAWSCredsJSON_InvalidJSON(t *testing.T) {
	result := formatAWSCredsJSON("not json")
	if !strings.Contains(result, "Raw:") {
		t.Error("expected Raw: fallback for invalid JSON")
	}
}

func TestFormatAWSCredsJSON_TokenTruncation(t *testing.T) {
	longToken := strings.Repeat("A", 100)
	jsonStr := fmt.Sprintf(`{"Token": "%s"}`, longToken)
	result := formatAWSCredsJSON(jsonStr)
	if strings.Contains(result, longToken) {
		t.Error("token should be truncated")
	}
	if !strings.Contains(result, "...") {
		t.Error("truncated token should have ...")
	}
}

// --- formatAWSIdentityJSON tests ---

func TestFormatAWSIdentityJSON_FullDocument(t *testing.T) {
	jsonStr := `{
		"accountId": "123456789012",
		"instanceId": "i-0abcdef1234567890",
		"instanceType": "t3.micro",
		"region": "us-east-1",
		"availabilityZone": "us-east-1a",
		"architecture": "x86_64",
		"imageId": "ami-12345678",
		"privateIp": "172.31.0.10"
	}`
	result := formatAWSIdentityJSON(jsonStr)
	for _, expected := range []string{"123456789012", "i-0abcdef1234567890", "t3.micro", "us-east-1", "x86_64"} {
		if !strings.Contains(result, expected) {
			t.Errorf("missing %q in output", expected)
		}
	}
}

func TestFormatAWSIdentityJSON_PartialFields(t *testing.T) {
	jsonStr := `{"accountId": "111111111111", "region": "eu-west-1"}`
	result := formatAWSIdentityJSON(jsonStr)
	if !strings.Contains(result, "111111111111") {
		t.Error("missing accountId")
	}
	if !strings.Contains(result, "eu-west-1") {
		t.Error("missing region")
	}
}

func TestFormatAWSIdentityJSON_InvalidJSON(t *testing.T) {
	result := formatAWSIdentityJSON("invalid")
	if !strings.Contains(result, "invalid") {
		t.Error("expected raw text for invalid JSON")
	}
}

func TestFormatAWSIdentityJSON_FieldOrder(t *testing.T) {
	jsonStr := `{"region": "ap-southeast-1", "accountId": "999999999999"}`
	result := formatAWSIdentityJSON(jsonStr)
	acctIdx := strings.Index(result, "accountId")
	regionIdx := strings.Index(result, "region")
	if acctIdx == -1 || regionIdx == -1 {
		t.Fatal("missing expected fields")
	}
	if acctIdx > regionIdx {
		t.Error("accountId should appear before region in formatted output")
	}
}

// --- formatAzureInstanceJSON tests ---

func TestFormatAzureInstanceJSON_Full(t *testing.T) {
	jsonStr := `{
		"compute": {
			"name": "myVM",
			"vmId": "12345-abcde",
			"vmSize": "Standard_D2s_v3",
			"location": "eastus",
			"resourceGroupName": "myRG",
			"subscriptionId": "sub-12345",
			"osType": "Linux"
		}
	}`
	result := formatAzureInstanceJSON(jsonStr)
	for _, expected := range []string{"myVM", "12345-abcde", "Standard_D2s_v3", "eastus", "myRG"} {
		if !strings.Contains(result, expected) {
			t.Errorf("missing %q in Azure instance output", expected)
		}
	}
}

func TestFormatAzureInstanceJSON_WithTags(t *testing.T) {
	jsonStr := `{
		"compute": {
			"name": "taggedVM",
			"tagsList": [
				{"name": "env", "value": "prod"},
				{"name": "team", "value": "security"}
			]
		}
	}`
	result := formatAzureInstanceJSON(jsonStr)
	if !strings.Contains(result, "Tags:") {
		t.Error("missing Tags section")
	}
	if !strings.Contains(result, "env = prod") {
		t.Error("missing env tag")
	}
	if !strings.Contains(result, "team = security") {
		t.Error("missing team tag")
	}
}

func TestFormatAzureInstanceJSON_NoCompute(t *testing.T) {
	result := formatAzureInstanceJSON(`{"network": {}}`)
	if result != "" {
		t.Errorf("expected empty for no compute section, got %q", result)
	}
}

func TestFormatAzureInstanceJSON_InvalidJSON(t *testing.T) {
	result := formatAzureInstanceJSON("not json at all")
	if !strings.Contains(result, "not json") {
		t.Error("expected raw text for invalid JSON")
	}
}

func TestFormatAzureInstanceJSON_EmptyCompute(t *testing.T) {
	result := formatAzureInstanceJSON(`{"compute": {}}`)
	if result != "" {
		t.Errorf("expected empty for empty compute, got %q", result)
	}
}

// --- formatAzureTokenJSON tests ---

func TestFormatAzureTokenJSON_Full(t *testing.T) {
	jsonStr := `{
		"access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6InEtMjNmYWxldlpo",
		"resource": "https://management.azure.com/",
		"expires_on": "1623753600"
	}`
	result := formatAzureTokenJSON(jsonStr)
	if !strings.Contains(result, "Managed Identity Token") {
		t.Error("missing token header")
	}
	if !strings.Contains(result, "Access Token:") {
		t.Error("missing access token")
	}
	if !strings.Contains(result, "management.azure.com") {
		t.Error("missing resource")
	}
	if !strings.Contains(result, "1623753600") {
		t.Error("missing expires_on")
	}
}

func TestFormatAzureTokenJSON_InvalidJSON(t *testing.T) {
	result := formatAzureTokenJSON("not-json")
	if !strings.Contains(result, "raw") {
		t.Errorf("expected 'raw' fallback for invalid JSON, got %q", result)
	}
}

func TestFormatAzureTokenJSON_EmptyFields(t *testing.T) {
	result := formatAzureTokenJSON(`{}`)
	if !strings.Contains(result, "Managed Identity Token") {
		t.Error("missing header even for empty token")
	}
}

// --- formatAzureNetworkJSON tests ---

func TestFormatAzureNetworkJSON_Full(t *testing.T) {
	jsonStr := `{
		"network": {
			"interface": [{
				"macAddress": "00:0D:3A:12:34:56",
				"ipv4": {
					"ipAddress": [{"privateIpAddress": "10.0.0.4", "publicIpAddress": "52.168.1.1"}],
					"subnet": [{"address": "10.0.0.0", "prefix": "24"}]
				}
			}]
		}
	}`
	result := formatAzureNetworkJSON(jsonStr)
	if !strings.Contains(result, "00:0D:3A:12:34:56") {
		t.Error("missing MAC address")
	}
	if !strings.Contains(result, "10.0.0.4") {
		t.Error("missing private IP")
	}
	if !strings.Contains(result, "52.168.1.1") {
		t.Error("missing public IP")
	}
	if !strings.Contains(result, "10.0.0.0/24") {
		t.Error("missing subnet")
	}
}

func TestFormatAzureNetworkJSON_NoNetwork(t *testing.T) {
	result := formatAzureNetworkJSON(`{"compute": {}}`)
	if result != "" {
		t.Errorf("expected empty for no network, got %q", result)
	}
}

func TestFormatAzureNetworkJSON_MultipleInterfaces(t *testing.T) {
	jsonStr := `{
		"network": {
			"interface": [
				{"macAddress": "AA:BB:CC:DD:EE:01", "ipv4": {"ipAddress": [{"privateIpAddress": "10.0.0.4"}]}},
				{"macAddress": "AA:BB:CC:DD:EE:02", "ipv4": {"ipAddress": [{"privateIpAddress": "10.0.1.4"}]}}
			]
		}
	}`
	result := formatAzureNetworkJSON(jsonStr)
	if !strings.Contains(result, "Interface 0") {
		t.Error("missing Interface 0")
	}
	if !strings.Contains(result, "Interface 1") {
		t.Error("missing Interface 1")
	}
}

func TestFormatAzureNetworkJSON_InvalidJSON(t *testing.T) {
	result := formatAzureNetworkJSON("bad json")
	if result != "" {
		t.Errorf("expected empty for invalid JSON, got %q", result)
	}
}

// --- formatGCPTokenJSON tests ---

func TestFormatGCPTokenJSON_Full(t *testing.T) {
	jsonStr := `{
		"access_token": "ya29.c.ElqABcdefghijklmnopqrstuvwxyz",
		"expires_in": 3600,
		"token_type": "Bearer"
	}`
	result := formatGCPTokenJSON(jsonStr)
	if !strings.Contains(result, "Access Token:") {
		t.Error("missing access token")
	}
	if !strings.Contains(result, "Expires In:") {
		t.Error("missing expires_in")
	}
	if !strings.Contains(result, "3600") {
		t.Error("missing expiry value")
	}
}

func TestFormatGCPTokenJSON_InvalidJSON(t *testing.T) {
	result := formatGCPTokenJSON("bad json")
	if result != "" {
		t.Errorf("expected empty for invalid JSON, got %q", result)
	}
}

func TestFormatGCPTokenJSON_EmptyFields(t *testing.T) {
	result := formatGCPTokenJSON(`{}`)
	if result != "" {
		t.Errorf("expected empty for empty JSON, got %q", result)
	}
}

// --- formatDOMetadataJSON tests ---

func TestFormatDOMetadataJSON_Full(t *testing.T) {
	jsonStr := `{
		"droplet_id": 12345678,
		"hostname": "my-droplet",
		"region": "nyc1",
		"interfaces": {
			"public": [{
				"ipv4": {"ip_address": "159.65.0.1"},
				"mac": "AA:BB:CC:DD:EE:FF"
			}]
		}
	}`
	result := formatDOMetadataJSON(jsonStr)
	if !strings.Contains(result, "1.2345678e+07") && !strings.Contains(result, "12345678") {
		t.Error("missing droplet_id")
	}
	if !strings.Contains(result, "my-droplet") {
		t.Error("missing hostname")
	}
	if !strings.Contains(result, "nyc1") {
		t.Error("missing region")
	}
}

func TestFormatDOMetadataJSON_InvalidJSON(t *testing.T) {
	result := formatDOMetadataJSON("not json")
	if !strings.Contains(result, "not json") {
		t.Error("expected raw content for invalid JSON")
	}
}

func TestFormatDOMetadataJSON_EmptyObject(t *testing.T) {
	result := formatDOMetadataJSON(`{}`)
	if result != "" {
		t.Errorf("expected empty for empty JSON, got %q", result)
	}
}

// --- formatDONetworkJSON tests ---

func TestFormatDONetworkJSON_Full(t *testing.T) {
	jsonStr := `{
		"interfaces": {
			"public": [{
				"ipv4": {"ip_address": "159.65.0.1", "netmask": "255.255.240.0", "gateway": "159.65.0.1"},
				"mac": "AA:BB:CC:DD:EE:FF"
			}],
			"private": [{
				"ipv4": {"ip_address": "10.132.0.2", "netmask": "255.255.0.0", "gateway": "10.132.0.1"},
				"mac": "11:22:33:44:55:66"
			}]
		}
	}`
	result := formatDONetworkJSON(jsonStr)
	if !strings.Contains(result, "159.65.0.1") {
		t.Error("missing public IP")
	}
	if !strings.Contains(result, "10.132.0.2") {
		t.Error("missing private IP")
	}
	if !strings.Contains(result, "AA:BB:CC:DD:EE:FF") {
		t.Error("missing public MAC")
	}
}

func TestFormatDONetworkJSON_NoInterfaces(t *testing.T) {
	result := formatDONetworkJSON(`{"droplet_id": 123}`)
	if result != "" {
		t.Errorf("expected empty for no interfaces, got %q", result)
	}
}

func TestFormatDONetworkJSON_InvalidJSON(t *testing.T) {
	result := formatDONetworkJSON("bad")
	if result != "" {
		t.Errorf("expected empty for invalid JSON, got %q", result)
	}
}

// --- Integration-style tests with mock metadata server ---

func TestMetadataGet_AWSStyleEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/latest/meta-data/instance-id", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("i-0abcdef1234567890"))
	})
	mux.HandleFunc("/latest/meta-data/placement/region", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("us-east-1"))
	})
	mux.HandleFunc("/latest/meta-data/iam/security-credentials/my-role", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"AccessKeyId":"AKIAEXAMPLE","SecretAccessKey":"secret","Token":"tok","Expiration":"2025-12-31T23:59:59Z"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	id := metadataGet(server.URL+"/latest/meta-data/instance-id", 3*time.Second, nil)
	if id != "i-0abcdef1234567890" {
		t.Errorf("instance-id = %q, want i-0abcdef1234567890", id)
	}

	region := metadataGet(server.URL+"/latest/meta-data/placement/region", 3*time.Second, nil)
	if region != "us-east-1" {
		t.Errorf("region = %q, want us-east-1", region)
	}

	creds := metadataGet(server.URL+"/latest/meta-data/iam/security-credentials/my-role", 3*time.Second, nil)
	formatted := formatAWSCredsJSON(creds)
	if !strings.Contains(formatted, "AKIAEXAMPLE") {
		t.Error("missing AccessKeyId in formatted creds")
	}
}

func TestMetadataGet_GCPStyleEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/computeMetadata/v1/project/project-id":
			w.Write([]byte("my-gcp-project"))
		case "/computeMetadata/v1/instance/zone":
			w.Write([]byte("projects/123/zones/us-central1-a"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	noHeader := metadataGet(server.URL+"/computeMetadata/v1/project/project-id", 3*time.Second, nil)
	if noHeader != "" {
		t.Error("GCP should reject requests without Metadata-Flavor header")
	}

	withHeader := metadataGet(server.URL+"/computeMetadata/v1/project/project-id", 3*time.Second,
		map[string]string{"Metadata-Flavor": "Google"})
	if withHeader != "my-gcp-project" {
		t.Errorf("GCP project-id = %q, want my-gcp-project", withHeader)
	}
}

func TestMetadataPut_AWSIMDSv2Token(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
			w.WriteHeader(400)
			return
		}
		w.Write([]byte("AQAEALnBi5ggOSV_TOKEN"))
	}))
	defer server.Close()

	token := metadataPut(server.URL, 3*time.Second, map[string]string{
		"X-aws-ec2-metadata-token-ttl-seconds": "21600",
	})
	if token != "AQAEALnBi5ggOSV_TOKEN" {
		t.Errorf("IMDSv2 token = %q, want AQAEALnBi5ggOSV_TOKEN", token)
	}
}

func TestMetadataGet_AzureStyleEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			w.WriteHeader(400)
			return
		}
		w.Write([]byte(`{"compute":{"name":"testVM","location":"westus2"}}`))
	}))
	defer server.Close()

	resp := metadataGet(server.URL, 3*time.Second, map[string]string{"Metadata": "true"})
	formatted := formatAzureInstanceJSON(resp)
	if !strings.Contains(formatted, "testVM") {
		t.Error("missing VM name in formatted Azure response")
	}
	if !strings.Contains(formatted, "westus2") {
		t.Error("missing location in formatted Azure response")
	}
}
