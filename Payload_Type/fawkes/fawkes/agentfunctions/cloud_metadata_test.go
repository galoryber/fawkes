package agentfunctions

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseAWSAccessKeys_Valid(t *testing.T) {
	input := `[+] AWS IAM Role: ec2-admin
AccessKeyId: AKIAIOSFODNN7EXAMPLE
SecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

	c := parseAWSAccessKeys(input)
	if c == nil {
		t.Fatal("expected credential")
	}
	if !strings.Contains(c.Account, "ec2-admin") {
		t.Errorf("expected role in account, got %q", c.Account)
	}
	if !strings.Contains(c.Credential, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("expected access key in credential, got %q", c.Credential)
	}
	if c.CredType != "key" {
		t.Errorf("expected key type, got %q", c.CredType)
	}
}

func TestParseAWSAccessKeys_NoRole(t *testing.T) {
	input := `AccessKeyId: AKIAIOSFODNN7EXAMPLE
SecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

	c := parseAWSAccessKeys(input)
	if c == nil {
		t.Fatal("expected credential")
	}
	if c.Account != "AWS IAM" {
		t.Errorf("expected 'AWS IAM' without role, got %q", c.Account)
	}
}

func TestParseAWSAccessKeys_MissingSecret(t *testing.T) {
	input := "AccessKeyId: AKIAIOSFODNN7EXAMPLE"
	c := parseAWSAccessKeys(input)
	if c != nil {
		t.Error("expected nil for missing secret key")
	}
}

func TestParseAWSAccessKeys_Empty(t *testing.T) {
	c := parseAWSAccessKeys("")
	if c != nil {
		t.Error("expected nil for empty input")
	}
}

func TestDetectCloudProvider_Azure(t *testing.T) {
	if p := detectCloudProvider("Azure Managed Identity token: ..."); p != "Azure" {
		t.Errorf("expected Azure, got %q", p)
	}
}

func TestDetectCloudProvider_GCP(t *testing.T) {
	if p := detectCloudProvider("GCP metadata response"); p != "GCP" {
		t.Errorf("expected GCP, got %q", p)
	}
}

func TestDetectCloudProvider_Google(t *testing.T) {
	if p := detectCloudProvider("google compute engine metadata"); p != "GCP" {
		t.Errorf("expected GCP for 'google', got %q", p)
	}
}

func TestDetectCloudProvider_Default(t *testing.T) {
	if p := detectCloudProvider("some metadata response"); p != "Cloud" {
		t.Errorf("expected Cloud, got %q", p)
	}
}

func TestParseCloudToken_AzureToken(t *testing.T) {
	input := `Azure Managed Identity
access_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imk2bEdrM0`

	c := parseCloudToken(input)
	if c == nil {
		t.Fatal("expected credential")
	}
	if !strings.Contains(c.Account, "Azure") {
		t.Errorf("expected Azure in account, got %q", c.Account)
	}
	if c.CredType != "token" {
		t.Errorf("expected token type, got %q", c.CredType)
	}
}

func TestParseCloudToken_ShortToken(t *testing.T) {
	input := "access_token: short"
	c := parseCloudToken(input)
	if c != nil {
		t.Error("expected nil for short token")
	}
}

func TestParseCloudToken_NoToken(t *testing.T) {
	c := parseCloudToken("no token here")
	if c != nil {
		t.Error("expected nil for no token")
	}
}

func TestParsePersistCredential_AWS(t *testing.T) {
	input := `SUCCESS: Created AWS access key
Account: backdoor-user
AccessKey: AKIA1234567890EXAMPL
SecretKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

	c := parsePersistCredential(input)
	if c == nil {
		t.Fatal("expected credential")
	}
	if !strings.Contains(c.Account, "AWS Persist") {
		t.Errorf("expected 'AWS Persist' in account, got %q", c.Account)
	}
	if !strings.Contains(c.Account, "backdoor-user") {
		t.Errorf("expected backdoor-user in account, got %q", c.Account)
	}
}

func TestParsePersistCredential_Azure(t *testing.T) {
	input := `SUCCESS: Created Azure service principal
App ID: 12345678-1234-1234-1234-123456789012
Secret: abc123def456
Account: malicious-app`

	c := parsePersistCredential(input)
	if c == nil {
		t.Fatal("expected credential")
	}
	if !strings.Contains(c.Account, "Azure") {
		t.Errorf("expected Azure provider, got %q", c.Account)
	}
}

func TestParsePersistCredential_MissingKey(t *testing.T) {
	input := "SUCCESS: Created\nAccount: test"
	c := parsePersistCredential(input)
	if c != nil {
		t.Error("expected nil for missing key/secret")
	}
}

func TestCloudStorageListingParsing(t *testing.T) {
	t.Run("single AWS listing", func(t *testing.T) {
		listing := cloudStorageListing{
			Action:   "cloud-storage",
			Provider: "aws",
			Host:     "s3.us-east-1.amazonaws.com",
			Role:     "my-role",
			Region:   "us-east-1",
			Buckets: []cloudBucketEntry{
				{
					Name:    "my-bucket",
					URI:     "s3://my-bucket",
					Created: "2025-01-01T00:00:00Z",
					Objects: []cloudObjectEntry{
						{Name: "file1.txt", Size: 1024},
						{Name: "dir/file2.txt", Size: 2048},
					},
				},
			},
		}

		data, err := json.Marshal(listing)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var single cloudStorageListing
		if err := json.Unmarshal(data, &single); err != nil {
			t.Fatalf("unmarshal single failed: %v", err)
		}
		if single.Action != "cloud-storage" {
			t.Errorf("action = %q, want cloud-storage", single.Action)
		}
		if single.Provider != "aws" {
			t.Errorf("provider = %q, want aws", single.Provider)
		}
		if single.Host != "s3.us-east-1.amazonaws.com" {
			t.Errorf("host = %q, want s3.us-east-1.amazonaws.com", single.Host)
		}
		if len(single.Buckets) != 1 {
			t.Fatalf("buckets = %d, want 1", len(single.Buckets))
		}
		if len(single.Buckets[0].Objects) != 2 {
			t.Errorf("objects = %d, want 2", len(single.Buckets[0].Objects))
		}
	})

	t.Run("array of listings", func(t *testing.T) {
		listings := []cloudStorageListing{
			{Action: "cloud-storage", Provider: "aws", Host: "s3.amazonaws.com"},
			{Action: "cloud-storage", Provider: "gcp", Host: "storage.googleapis.com", Project: "my-proj"},
		}

		data, err := json.Marshal(listings)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var parsed []cloudStorageListing
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("unmarshal array failed: %v", err)
		}
		if len(parsed) != 2 {
			t.Fatalf("listings = %d, want 2", len(parsed))
		}
		if parsed[1].Project != "my-proj" {
			t.Errorf("project = %q, want my-proj", parsed[1].Project)
		}
	})

	t.Run("error listing has no buckets", func(t *testing.T) {
		listing := cloudStorageListing{
			Action:   "cloud-storage",
			Provider: "aws",
			Error:    "No IAM role attached",
		}

		data, _ := json.Marshal(listing)
		var parsed cloudStorageListing
		json.Unmarshal(data, &parsed)

		if parsed.Error != "No IAM role attached" {
			t.Errorf("error = %q", parsed.Error)
		}
		if len(parsed.Buckets) != 0 {
			t.Errorf("error listing should have no buckets, got %d", len(parsed.Buckets))
		}
	})

	t.Run("object path splitting for file browser", func(t *testing.T) {
		tests := []struct {
			name       string
			objectName string
			bucket     string
			wantParent string
			wantName   string
		}{
			{"simple", "file.txt", "bkt", "/bkt", "file.txt"},
			{"nested", "dir/sub/file.txt", "bkt", "/bkt/dir/sub", "file.txt"},
			{"single prefix", "logs/app.log", "data", "/data/logs", "app.log"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				objName := tt.objectName
				objParent := "/" + tt.bucket
				if idx := strings.LastIndex(tt.objectName, "/"); idx > 0 {
					objParent = "/" + tt.bucket + "/" + tt.objectName[:idx]
					objName = tt.objectName[idx+1:]
				}
				if objParent != tt.wantParent {
					t.Errorf("parent = %q, want %q", objParent, tt.wantParent)
				}
				if objName != tt.wantName {
					t.Errorf("name = %q, want %q", objName, tt.wantName)
				}
			})
		}
	})
}
