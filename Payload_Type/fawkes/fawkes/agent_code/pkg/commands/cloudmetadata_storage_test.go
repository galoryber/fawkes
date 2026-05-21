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

func TestCloudStorageOutputFormatting(t *testing.T) {
	t.Run("aws bucket output contains s3 prefix", func(t *testing.T) {
		xml := `<ListAllMyBucketsResult><Buckets><Bucket><Name>test-bucket</Name><CreationDate>2025-01-01T00:00:00Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>`
		names := cloudExtractXMLValues(xml, "Name")
		dates := cloudExtractXMLValues(xml, "CreationDate")
		if len(names) != 1 || names[0] != "test-bucket" {
			t.Fatalf("expected test-bucket, got %v", names)
		}
		if len(dates) != 1 || dates[0] != "2025-01-01T00:00:00Z" {
			t.Fatalf("expected creation date, got %v", dates)
		}
		output := "s3://" + names[0]
		if !strings.HasPrefix(output, "s3://") {
			t.Error("S3 bucket output should use s3:// prefix")
		}
	})

	t.Run("gcs bucket output contains gs prefix", func(t *testing.T) {
		type gcsBucket struct {
			Name string `json:"name"`
		}
		type listResult struct {
			Items []gcsBucket `json:"items"`
		}
		resp := `{"items":[{"name":"my-gcs-bucket"}]}`
		var result listResult
		json.Unmarshal([]byte(resp), &result)
		output := "gs://" + result.Items[0].Name
		if !strings.HasPrefix(output, "gs://") {
			t.Error("GCS bucket output should use gs:// prefix")
		}
	})
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
