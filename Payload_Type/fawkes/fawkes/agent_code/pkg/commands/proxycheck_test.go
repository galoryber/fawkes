package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestProxyCheckNoParams(t *testing.T) {
	cmd := &ProxyCheckCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Proxy Configuration") {
		t.Fatalf("expected proxy config header, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Environment Variables") {
		t.Fatalf("expected env vars section, got: %s", result.Output)
	}
}

func TestProxyCheckWithParams(t *testing.T) {
	params, _ := json.Marshal(proxyCheckArgs{})
	cmd := &ProxyCheckCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
}

func TestProxyCheckTransportDetection(t *testing.T) {
	cmd := &ProxyCheckCommand{}
	result := cmd.Execute(structs.Task{Params: "{}"})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
	// Should always contain transport detection section
	if !strings.Contains(result.Output, "Transport") || !strings.Contains(result.Output, "Proxy") {
		t.Fatalf("expected transport proxy section, got: %s", result.Output)
	}
}
