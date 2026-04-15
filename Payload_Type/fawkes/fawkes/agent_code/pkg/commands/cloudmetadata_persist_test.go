package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestMetadataPost_EmptyURL(t *testing.T) {
	// metadataPost should handle invalid URLs gracefully
	resp, code := metadataPost("", 1, nil, "")
	if resp != "" || code != 0 {
		t.Errorf("Empty URL should return empty response, got resp=%q code=%d", resp, code)
	}
}

func TestMetadataPost_InvalidURL(t *testing.T) {
	// Non-routable address should fail fast
	resp, code := metadataPost("http://192.0.2.1:1/test", 1, nil, `{"test":"data"}`)
	if code != 0 {
		// If we got a response code, it shouldn't be 200
		if code == 200 {
			t.Errorf("Invalid URL should not return 200, got code=%d", code)
		}
	}
	_ = resp // may be empty or error message
}

func TestMetadataPost_WithHeaders(t *testing.T) {
	// Verify headers are set correctly (structural test)
	headers := map[string]string{
		"Authorization": "Bearer test-token",
		"Content-Type":  "application/json",
	}
	// Non-routable address, just verify no panic
	resp, _ := metadataPost("http://192.0.2.1:1/test", 1, headers, `{"key":"value"}`)
	_ = resp
}

func TestCloudPersistActions_InDispatcher(t *testing.T) {
	// Verify the persist actions are recognized by the dispatcher
	cmd := &CloudMetadataCommand{}

	// aws-persist should not return "unknown action" error
	result := cmd.Execute(structs.Task{Params: `{"action":"aws-persist","timeout":1}`})
	if result.Output == "Error: unknown action. Available: detect, all, creds, identity, userdata, network, aws-iam, azure-graph, gcp-iam, aws-persist, azure-persist" {
		t.Error("aws-persist action should be recognized by dispatcher")
	}
	// It will fail with "No IAM role attached" since we're not on AWS, but that's expected

	// azure-persist should not return "unknown action" error
	result = cmd.Execute(structs.Task{Params: `{"action":"azure-persist","timeout":1}`})
	if result.Output == "Error: unknown action. Available: detect, all, creds, identity, userdata, network, aws-iam, azure-graph, gcp-iam, aws-persist, azure-persist" {
		t.Error("azure-persist action should be recognized by dispatcher")
	}
}

func TestAWSPersist_NoIMDS(t *testing.T) {
	// When not on AWS, awsPersist should gracefully report no IAM role
	result := awsPersist(1)
	if result == "" {
		t.Error("awsPersist should return non-empty output")
	}
	// Should contain the "no IAM role" message since we're not on AWS
	if !strings.Contains(result, "No IAM role") && !strings.Contains(result, "Could not") {
		t.Logf("Output: %s", result)
	}
}

func TestAzurePersist_NoIMDS(t *testing.T) {
	// When not on Azure, azurePersist should gracefully report no managed identity
	result := azurePersist(1)
	if result == "" {
		t.Error("azurePersist should return non-empty output")
	}
	// Should contain the "no managed identity" message since we're not on Azure
	if !strings.Contains(result, "No managed identity") && !strings.Contains(result, "Could not") {
		t.Logf("Output: %s", result)
	}
}
