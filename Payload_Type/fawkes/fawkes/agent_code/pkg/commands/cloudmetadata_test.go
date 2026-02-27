package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestCloudMetadataNoParams(t *testing.T) {
	cmd := &CloudMetadataCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	// With no params, defaults to "detect" action which should return something
	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Cloud Instance Detection") {
		t.Fatalf("expected detection output, got: %s", result.Output)
	}
}

func TestCloudMetadataDetectNoCloud(t *testing.T) {
	params, _ := json.Marshal(cloudMetadataArgs{Action: "detect", Timeout: 1})
	cmd := &CloudMetadataCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
	// On a non-cloud machine, should report no detection
	if !strings.Contains(result.Output, "No cloud metadata service detected") && !strings.Contains(result.Output, "detected") {
		t.Fatalf("expected detection result, got: %s", result.Output)
	}
}

func TestCloudMetadataInvalidAction(t *testing.T) {
	params, _ := json.Marshal(cloudMetadataArgs{Action: "invalid"})
	cmd := &CloudMetadataCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Fatalf("expected error for invalid action, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "unknown action") {
		t.Fatalf("expected unknown action error, got: %s", result.Output)
	}
}

func TestCloudMetadataInvalidProvider(t *testing.T) {
	params, _ := json.Marshal(cloudMetadataArgs{Action: "all", Provider: "invalid_provider", Timeout: 1})
	cmd := &CloudMetadataCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "not available") {
		t.Fatalf("expected not available message, got: %s", result.Output)
	}
}

func TestMetadataGet(t *testing.T) {
	// Create a mock metadata server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/test":
			fmt.Fprint(w, "test-value")
		case "/test-header":
			if r.Header.Get("X-Custom") == "expected" {
				fmt.Fprint(w, "header-ok")
			} else {
				http.Error(w, "missing header", 403)
			}
		case "/not-found":
			http.Error(w, "not found", 404)
		default:
			http.Error(w, "not found", 404)
		}
	}))
	defer server.Close()

	// Test basic GET
	val := metadataGet(server.URL+"/test", 3e9, nil)
	if val != "test-value" {
		t.Fatalf("expected 'test-value', got '%s'", val)
	}

	// Test with header
	val = metadataGet(server.URL+"/test-header", 3e9, map[string]string{"X-Custom": "expected"})
	if val != "header-ok" {
		t.Fatalf("expected 'header-ok', got '%s'", val)
	}

	// Test 404
	val = metadataGet(server.URL+"/not-found", 3e9, nil)
	if val != "" {
		t.Fatalf("expected empty for 404, got '%s'", val)
	}

	// Test unreachable
	val = metadataGet("http://192.0.2.1:1/unreachable", 1e9, nil)
	if val != "" {
		t.Fatalf("expected empty for unreachable, got '%s'", val)
	}
}

func TestMetadataPut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" && r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "21600" {
			fmt.Fprint(w, "mock-token-123")
		} else {
			http.Error(w, "bad request", 400)
		}
	}))
	defer server.Close()

	val := metadataPut(server.URL, 3e9, map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
	if val != "mock-token-123" {
		t.Fatalf("expected 'mock-token-123', got '%s'", val)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		n        int
		expected string
	}{
		{"hello world", 5, "hello"},
		{"short", 10, "short"},
		{"", 5, ""},
		{"exactly", 7, "exactly"},
	}

	for _, tt := range tests {
		result := truncate(tt.input, tt.n)
		if result != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.n, result, tt.expected)
		}
	}
}

func TestResolveProviders(t *testing.T) {
	// Specific provider
	providers := resolveProviders("aws", 1e9)
	if len(providers) != 1 || providers[0] != "aws" {
		t.Fatalf("expected [aws], got %v", providers)
	}

	providers = resolveProviders("azure", 1e9)
	if len(providers) != 1 || providers[0] != "azure" {
		t.Fatalf("expected [azure], got %v", providers)
	}

	providers = resolveProviders("gcp", 1e9)
	if len(providers) != 1 || providers[0] != "gcp" {
		t.Fatalf("expected [gcp], got %v", providers)
	}

	// Invalid provider
	providers = resolveProviders("invalid", 1e9)
	if providers != nil {
		t.Fatalf("expected nil for invalid, got %v", providers)
	}
}

func TestCloudMetadataCredsNoCloud(t *testing.T) {
	params, _ := json.Marshal(cloudMetadataArgs{Action: "creds", Timeout: 1})
	cmd := &CloudMetadataCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
}

func TestCloudMetadataIdentityNoCloud(t *testing.T) {
	params, _ := json.Marshal(cloudMetadataArgs{Action: "identity", Timeout: 1})
	cmd := &CloudMetadataCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
}

func TestCloudMetadataUserdataNoCloud(t *testing.T) {
	params, _ := json.Marshal(cloudMetadataArgs{Action: "userdata", Timeout: 1})
	cmd := &CloudMetadataCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
}

func TestCloudMetadataNetworkNoCloud(t *testing.T) {
	params, _ := json.Marshal(cloudMetadataArgs{Action: "network", Timeout: 1})
	cmd := &CloudMetadataCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
}
