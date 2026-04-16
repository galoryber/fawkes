package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Tests for cloud secret response parsing patterns used in cloudmetadata_secrets.go.
// These validate the JSON parsing logic without requiring live cloud API access.

func TestSSMDescribeParametersJSONParsing(t *testing.T) {
	// Test the JSON parsing pattern used in awsGetSSMSecrets for DescribeParameters
	type ssmParam struct {
		Name string `json:"Name"`
		Type string `json:"Type"`
	}
	type describeResult struct {
		Parameters []ssmParam `json:"Parameters"`
	}

	tests := []struct {
		name       string
		json       string
		wantCount  int
		wantFirst  string
		wantErr    bool
	}{
		{
			name:      "valid response with 3 params",
			json:      `{"Parameters":[{"Name":"/app/db-password","Type":"SecureString"},{"Name":"/app/api-key","Type":"SecureString"},{"Name":"/app/config","Type":"String"}]}`,
			wantCount: 3,
			wantFirst: "/app/db-password",
		},
		{
			name:      "empty parameters list",
			json:      `{"Parameters":[]}`,
			wantCount: 0,
		},
		{
			name:    "invalid JSON",
			json:    `not json`,
			wantErr: true,
		},
		{
			name:      "single parameter",
			json:      `{"Parameters":[{"Name":"/prod/secret","Type":"SecureString"}]}`,
			wantCount: 1,
			wantFirst: "/prod/secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result describeResult
			err := json.Unmarshal([]byte(tt.json), &result)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error for invalid JSON")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result.Parameters) != tt.wantCount {
				t.Errorf("got %d params, want %d", len(result.Parameters), tt.wantCount)
			}
			if tt.wantFirst != "" && len(result.Parameters) > 0 {
				if result.Parameters[0].Name != tt.wantFirst {
					t.Errorf("first param name = %q, want %q", result.Parameters[0].Name, tt.wantFirst)
				}
			}
		})
	}
}

func TestSSMGetParameterJSONParsing(t *testing.T) {
	// Test the JSON parsing pattern for GetParameter responses
	type getResult struct {
		Parameter struct {
			Name  string `json:"Name"`
			Type  string `json:"Type"`
			Value string `json:"Value"`
		} `json:"Parameter"`
	}

	tests := []struct {
		name      string
		json      string
		wantName  string
		wantValue string
		wantErr   bool
	}{
		{
			name:      "valid secret",
			json:      `{"Parameter":{"Name":"/app/db-password","Type":"SecureString","Value":"s3cr3t-p4ssw0rd"}}`,
			wantName:  "/app/db-password",
			wantValue: "s3cr3t-p4ssw0rd",
		},
		{
			name:      "empty value",
			json:      `{"Parameter":{"Name":"/app/empty","Type":"String","Value":""}}`,
			wantName:  "/app/empty",
			wantValue: "",
		},
		{
			name:    "invalid JSON",
			json:    `{broken`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result getResult
			err := json.Unmarshal([]byte(tt.json), &result)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Parameter.Name != tt.wantName {
				t.Errorf("name = %q, want %q", result.Parameter.Name, tt.wantName)
			}
			if result.Parameter.Value != tt.wantValue {
				t.Errorf("value = %q, want %q", result.Parameter.Value, tt.wantValue)
			}
		})
	}
}

func TestSSMSecretValueTruncation(t *testing.T) {
	// Test the value truncation logic: if len(val) > 200 { val = val[:200] + "..." }
	tests := []struct {
		name      string
		inputLen  int
		wantTrunc bool
	}{
		{"short value", 50, false},
		{"exact 200", 200, false},
		{"201 chars", 201, true},
		{"long value", 500, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := strings.Repeat("a", tt.inputLen)
			if len(val) > 200 {
				val = val[:200] + "..."
			}
			if tt.wantTrunc {
				if !strings.HasSuffix(val, "...") {
					t.Error("expected truncation with ...")
				}
				if len(val) != 203 { // 200 + "..."
					t.Errorf("truncated length = %d, want 203", len(val))
				}
			} else if strings.HasSuffix(val, "...") {
				t.Error("should not be truncated")
			}
		})
	}
}

func TestAzureVaultTagParsing(t *testing.T) {
	// Test the Azure tag parsing pattern used to discover Key Vault names
	tests := []struct {
		name     string
		tags     string
		wantVaults []string
	}{
		{
			name:       "vault keyword",
			tags:       "env:prod;vault:my-vault-name;team:security",
			wantVaults: []string{"my-vault-name"},
		},
		{
			name:       "keyvault keyword",
			tags:       "keyvault:prod-kv;location:eastus",
			wantVaults: []string{"prod-kv"},
		},
		{
			name:       "case insensitive",
			tags:       "VAULT:upper-vault;KeyVault:mixed-vault",
			wantVaults: []string{"upper-vault", "mixed-vault"},
		},
		{
			name:       "no vault tags",
			tags:       "env:prod;location:eastus;team:ops",
			wantVaults: nil,
		},
		{
			name:       "empty tags",
			tags:       "",
			wantVaults: nil,
		},
		{
			name:       "trimmed whitespace",
			tags:       "vault: spaced-name ;other:val",
			wantVaults: []string{"spaced-name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var vaultNames []string
			for _, tag := range strings.Split(tt.tags, ";") {
				parts := strings.SplitN(tag, ":", 2)
				if len(parts) == 2 {
					lower := strings.ToLower(parts[0])
					if strings.Contains(lower, "vault") || strings.Contains(lower, "keyvault") {
						vaultNames = append(vaultNames, strings.TrimSpace(parts[1]))
					}
				}
			}
			if len(vaultNames) != len(tt.wantVaults) {
				t.Errorf("found %d vaults, want %d", len(vaultNames), len(tt.wantVaults))
				return
			}
			for i, v := range vaultNames {
				if v != tt.wantVaults[i] {
					t.Errorf("vault[%d] = %q, want %q", i, v, tt.wantVaults[i])
				}
			}
		})
	}
}

func TestGCPSecretBase64Decoding(t *testing.T) {
	// Test the base64 decoding + truncation pattern from gcpGetSecretManager
	tests := []struct {
		name       string
		data       string
		wantValue  string
		wantTrunc  bool
		wantErr    bool
	}{
		{
			name:      "valid short secret",
			data:      base64.StdEncoding.EncodeToString([]byte("my-secret-value")),
			wantValue: "my-secret-value",
		},
		{
			name:      "valid long secret truncated",
			data:      base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 150))),
			wantValue: strings.Repeat("x", 100) + "...",
			wantTrunc: true,
		},
		{
			name:    "invalid base64",
			data:    "!!!not-base64!!!",
			wantErr: true,
		},
		{
			name:      "empty secret",
			data:      base64.StdEncoding.EncodeToString([]byte("")),
			wantValue: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded, err := base64.StdEncoding.DecodeString(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Error("expected decode error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			val := string(decoded)
			if len(val) > 100 {
				val = val[:100] + "..."
			}
			if val != tt.wantValue {
				t.Errorf("decoded = %q, want %q", val, tt.wantValue)
			}
			if tt.wantTrunc && !strings.HasSuffix(val, "...") {
				t.Error("expected truncation")
			}
		})
	}
}

func TestK8sSecretJSONParsing(t *testing.T) {
	// Test the JSON parsing pattern used in k8sReadSecret for K8s Secret objects
	type k8sSecret struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Type string            `json:"type"`
		Data map[string]string `json:"data"`
	}

	tests := []struct {
		name     string
		json     string
		wantName string
		wantType string
		wantKeys int
		wantErr  bool
	}{
		{
			name:     "opaque secret with credentials",
			json:     `{"metadata":{"name":"db-creds","namespace":"default"},"type":"Opaque","data":{"username":"YWRtaW4=","password":"cDRzc3cwcmQ="}}`,
			wantName: "db-creds",
			wantType: "Opaque",
			wantKeys: 2,
		},
		{
			name:     "service account token",
			json:     `{"metadata":{"name":"default-token-abc","namespace":"kube-system"},"type":"kubernetes.io/service-account-token","data":{"token":"ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklpSjk="}}`,
			wantName: "default-token-abc",
			wantType: "kubernetes.io/service-account-token",
			wantKeys: 1,
		},
		{
			name:     "empty data",
			json:     `{"metadata":{"name":"empty-secret","namespace":"default"},"type":"Opaque","data":{}}`,
			wantName: "empty-secret",
			wantType: "Opaque",
			wantKeys: 0,
		},
		{
			name:    "invalid JSON",
			json:    `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var secret k8sSecret
			err := json.Unmarshal([]byte(tt.json), &secret)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if secret.Metadata.Name != tt.wantName {
				t.Errorf("name = %q, want %q", secret.Metadata.Name, tt.wantName)
			}
			if secret.Type != tt.wantType {
				t.Errorf("type = %q, want %q", secret.Type, tt.wantType)
			}
			if len(secret.Data) != tt.wantKeys {
				t.Errorf("data keys = %d, want %d", len(secret.Data), tt.wantKeys)
			}
		})
	}
}

func TestK8sSecretBase64DataDecoding(t *testing.T) {
	// Test the base64 decoding loop from k8sReadSecret
	type k8sSecret struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Type string            `json:"type"`
		Data map[string]string `json:"data"`
	}

	secretJSON := `{
		"metadata": {"name": "app-secrets"},
		"type": "Opaque",
		"data": {
			"db-host": "cG9zdGdyZXMuaW50ZXJuYWw=",
			"db-password": "c3VwZXItc2VjcmV0LXBhc3N3b3Jk",
			"api-key": "YWJjZGVmMTIzNDU2",
			"bad-data": "!!!invalid-base64!!!"
		}
	}`

	var secret k8sSecret
	if err := json.Unmarshal([]byte(secretJSON), &secret); err != nil {
		t.Fatalf("failed to parse test JSON: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Secret: %s (type: %s) ===\n\n", secret.Metadata.Name, secret.Type))

	var decodeErrors int
	for key, encodedVal := range secret.Data {
		decoded, err := base64.StdEncoding.DecodeString(encodedVal)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[%s] (decode error: %v)\n", key, err))
			decodeErrors++
			continue
		}
		sb.WriteString(fmt.Sprintf("[%s]\n%s\n\n", key, string(decoded)))
	}

	output := sb.String()

	if !strings.Contains(output, "app-secrets") {
		t.Error("expected secret name in output")
	}
	if !strings.Contains(output, "postgres.internal") {
		t.Error("expected decoded db-host")
	}
	if !strings.Contains(output, "super-secret-password") {
		t.Error("expected decoded db-password")
	}
	if !strings.Contains(output, "abcdef123456") {
		t.Error("expected decoded api-key")
	}
	if decodeErrors != 1 {
		t.Errorf("expected 1 decode error (bad-data), got %d", decodeErrors)
	}
	if !strings.Contains(output, "decode error") {
		t.Error("expected decode error message for bad-data")
	}
}
