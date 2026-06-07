package commands

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestS3ListBucketsXMLParsing(t *testing.T) {
	tests := []struct {
		name      string
		xml       string
		wantNames []string
	}{
		{
			name: "two buckets",
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Buckets>
    <Bucket><Name>my-app-data</Name><CreationDate>2025-01-15T10:30:00.000Z</CreationDate></Bucket>
    <Bucket><Name>my-logs</Name><CreationDate>2025-03-20T14:22:00.000Z</CreationDate></Bucket>
  </Buckets>
</ListAllMyBucketsResult>`,
			wantNames: []string{"my-app-data", "my-logs"},
		},
		{
			name:      "empty bucket list",
			xml:       `<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>`,
			wantNames: nil,
		},
		{
			name: "single bucket with objects",
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult>
  <Buckets>
    <Bucket><Name>prod-secrets</Name><CreationDate>2024-06-01T00:00:00.000Z</CreationDate></Bucket>
  </Buckets>
</ListAllMyBucketsResult>`,
			wantNames: []string{"prod-secrets"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := cloudExtractXMLValues(tt.xml, "Name")
			if len(names) != len(tt.wantNames) {
				t.Errorf("got %d names, want %d", len(names), len(tt.wantNames))
				return
			}
			for i, name := range names {
				if name != tt.wantNames[i] {
					t.Errorf("name[%d] = %q, want %q", i, name, tt.wantNames[i])
				}
			}
		})
	}
}

func TestS3ListObjectsXMLParsing(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Name>my-app-data</Name>
  <MaxKeys>5</MaxKeys>
  <Contents><Key>config/app.yaml</Key><Size>1024</Size></Contents>
  <Contents><Key>data/users.csv</Key><Size>51200</Size></Contents>
  <Contents><Key>secrets/api-keys.json</Key><Size>256</Size></Contents>
</ListBucketResult>`

	keys := cloudExtractXMLValues(xml, "Key")
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(keys))
	}
	expected := []string{"config/app.yaml", "data/users.csv", "secrets/api-keys.json"}
	for i, key := range keys {
		if key != expected[i] {
			t.Errorf("key[%d] = %q, want %q", i, key, expected[i])
		}
	}
}

func TestGCSListBucketsJSONParsing(t *testing.T) {
	type gcsBucket struct {
		Name         string `json:"name"`
		Location     string `json:"location"`
		StorageClass string `json:"storageClass"`
		TimeCreated  string `json:"timeCreated"`
	}
	type listResult struct {
		Items []gcsBucket `json:"items"`
	}

	tests := []struct {
		name      string
		json      string
		wantCount int
		wantFirst string
		wantErr   bool
	}{
		{
			name:      "two buckets",
			json:      `{"items":[{"name":"my-project-data","location":"US","storageClass":"STANDARD","timeCreated":"2025-01-15T10:30:00Z"},{"name":"my-project-logs","location":"US-EAST1","storageClass":"NEARLINE","timeCreated":"2025-03-20T14:22:00Z"}]}`,
			wantCount: 2,
			wantFirst: "my-project-data",
		},
		{
			name:      "empty items",
			json:      `{"items":[]}`,
			wantCount: 0,
		},
		{
			name:      "no items field",
			json:      `{}`,
			wantCount: 0,
		},
		{
			name:    "invalid json",
			json:    `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result listResult
			err := json.Unmarshal([]byte(tt.json), &result)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result.Items) != tt.wantCount {
				t.Errorf("got %d items, want %d", len(result.Items), tt.wantCount)
				return
			}
			if tt.wantFirst != "" && len(result.Items) > 0 {
				if result.Items[0].Name != tt.wantFirst {
					t.Errorf("first bucket = %q, want %q", result.Items[0].Name, tt.wantFirst)
				}
			}
		})
	}
}

func TestGCSListObjectsJSONParsing(t *testing.T) {
	type gcsObject struct {
		Name string `json:"name"`
		Size string `json:"size"`
	}
	type objectResult struct {
		Items []gcsObject `json:"items"`
	}

	resp := `{"items":[{"name":"data/file1.txt","size":"1024"},{"name":"config/settings.json","size":"512"},{"name":"backups/db-dump.sql","size":"1048576"}]}`
	var result objectResult
	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Items) != 3 {
		t.Fatalf("got %d items, want 3", len(result.Items))
	}
	if result.Items[0].Name != "data/file1.txt" {
		t.Errorf("first object = %q, want %q", result.Items[0].Name, "data/file1.txt")
	}
	if result.Items[2].Size != "1048576" {
		t.Errorf("third object size = %q, want %q", result.Items[2].Size, "1048576")
	}
}

func TestAzureBlobContainerXMLParsing(t *testing.T) {
	xml := `<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://myaccount.blob.core.windows.net/">
  <Containers>
    <Container><Name>documents</Name></Container>
    <Container><Name>backups</Name></Container>
    <Container><Name>logs</Name></Container>
  </Containers>
</EnumerationResults>`

	names := cloudExtractXMLValues(xml, "Name")
	if len(names) != 3 {
		t.Fatalf("got %d containers, want 3", len(names))
	}
	expected := []string{"documents", "backups", "logs"}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("container[%d] = %q, want %q", i, name, expected[i])
		}
	}
}

func TestAzureBlobListXMLParsing(t *testing.T) {
	xml := `<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ContainerName="documents">
  <Blobs>
    <Blob><Name>report.pdf</Name></Blob>
    <Blob><Name>spreadsheet.xlsx</Name></Blob>
  </Blobs>
</EnumerationResults>`

	names := cloudExtractXMLValues(xml, "Name")
	if len(names) != 2 {
		t.Fatalf("got %d blobs, want 2", len(names))
	}
	if names[0] != "report.pdf" || names[1] != "spreadsheet.xlsx" {
		t.Errorf("unexpected blobs: %v", names)
	}
}

func TestAzureStorageAccountNameGeneration(t *testing.T) {
	rg := "my-resource-group"
	clean := strings.ToLower(strings.ReplaceAll(rg, "-", ""))
	expected := "myresourcegroup"
	if clean != expected {
		t.Errorf("cleaned name = %q, want %q", clean, expected)
	}

	candidates := []string{clean, clean + "storage", clean + "sa"}
	if len(candidates) != 3 {
		t.Errorf("expected 3 candidates, got %d", len(candidates))
	}
	if candidates[1] != "myresourcegroupstorage" {
		t.Errorf("storage candidate = %q, want %q", candidates[1], "myresourcegroupstorage")
	}
}

func TestCloudStorageListingJSONFormat(t *testing.T) {
	t.Run("aws listing serializes correctly", func(t *testing.T) {
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

		var parsed cloudStorageListing
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if parsed.Action != "cloud-storage" {
			t.Errorf("action = %q, want %q", parsed.Action, "cloud-storage")
		}
		if parsed.Provider != "aws" {
			t.Errorf("provider = %q, want %q", parsed.Provider, "aws")
		}
		if parsed.Host != "s3.us-east-1.amazonaws.com" {
			t.Errorf("host = %q, want %q", parsed.Host, "s3.us-east-1.amazonaws.com")
		}
		if len(parsed.Buckets) != 1 {
			t.Fatalf("buckets = %d, want 1", len(parsed.Buckets))
		}
		if parsed.Buckets[0].Name != "my-bucket" {
			t.Errorf("bucket name = %q, want %q", parsed.Buckets[0].Name, "my-bucket")
		}
		if len(parsed.Buckets[0].Objects) != 2 {
			t.Fatalf("objects = %d, want 2", len(parsed.Buckets[0].Objects))
		}
		if parsed.Buckets[0].Objects[0].Size != 1024 {
			t.Errorf("object size = %d, want 1024", parsed.Buckets[0].Objects[0].Size)
		}
	})

	t.Run("gcp listing includes location and storage class", func(t *testing.T) {
		listing := cloudStorageListing{
			Action:   "cloud-storage",
			Provider: "gcp",
			Host:     "storage.googleapis.com",
			Project:  "my-project",
			Buckets: []cloudBucketEntry{
				{
					Name:         "my-gcs-bucket",
					URI:          "gs://my-gcs-bucket",
					Location:     "US-EAST1",
					StorageClass: "STANDARD",
					Created:      "2025-01-15T10:30:00Z",
				},
			},
		}

		data, err := json.Marshal(listing)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var parsed cloudStorageListing
		json.Unmarshal(data, &parsed)
		if parsed.Project != "my-project" {
			t.Errorf("project = %q, want %q", parsed.Project, "my-project")
		}
		if parsed.Buckets[0].Location != "US-EAST1" {
			t.Errorf("location = %q, want %q", parsed.Buckets[0].Location, "US-EAST1")
		}
		if parsed.Buckets[0].StorageClass != "STANDARD" {
			t.Errorf("storage_class = %q, want %q", parsed.Buckets[0].StorageClass, "STANDARD")
		}
	})

	t.Run("azure listing with multiple accounts", func(t *testing.T) {
		listings := []cloudStorageListing{
			{
				Action:   "cloud-storage",
				Provider: "azure",
				Host:     "myaccount.blob.core.windows.net",
				Account:  "myaccount",
				Buckets: []cloudBucketEntry{
					{Name: "container1", URI: "https://myaccount.blob.core.windows.net/container1"},
					{Name: "container2", URI: "https://myaccount.blob.core.windows.net/container2"},
				},
			},
		}

		data, err := json.Marshal(listings)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var parsed []cloudStorageListing
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("unmarshal array failed: %v", err)
		}
		if len(parsed) != 1 {
			t.Fatalf("listings = %d, want 1", len(parsed))
		}
		if parsed[0].Account != "myaccount" {
			t.Errorf("account = %q, want %q", parsed[0].Account, "myaccount")
		}
		if len(parsed[0].Buckets) != 2 {
			t.Errorf("containers = %d, want 2", len(parsed[0].Buckets))
		}
	})

	t.Run("error listing omits buckets", func(t *testing.T) {
		listing := cloudStorageListing{
			Action:   "cloud-storage",
			Provider: "aws",
			Error:    "No IAM role attached",
		}

		data, err := json.Marshal(listing)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		if !strings.Contains(string(data), `"error"`) {
			t.Error("error field not present in JSON")
		}
		if strings.Contains(string(data), `"buckets":[`) {
			t.Error("empty buckets should be null, not an array")
		}
	})

	t.Run("object size zero omitted", func(t *testing.T) {
		obj := cloudObjectEntry{Name: "test.txt"}
		data, _ := json.Marshal(obj)
		if strings.Contains(string(data), `"size"`) {
			t.Error("zero size should be omitted (omitempty)")
		}
	})
}

func TestCloudStorageObjectPathSplitting(t *testing.T) {
	tests := []struct {
		name       string
		objectName string
		bucket     string
		wantParent string
		wantName   string
	}{
		{"simple file", "file.txt", "my-bucket", "/my-bucket", "file.txt"},
		{"nested file", "dir/subdir/file.txt", "my-bucket", "/my-bucket/dir/subdir", "file.txt"},
		{"single dir prefix", "config/app.yaml", "data", "/data/config", "app.yaml"},
		{"deep nesting", "a/b/c/d/e.txt", "bkt", "/bkt/a/b/c/d", "e.txt"},
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
}
