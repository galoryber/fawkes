package commands

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type CurlCommand struct{}

func (c *CurlCommand) Name() string { return "curl" }
func (c *CurlCommand) Description() string {
	return "Make HTTP requests from the agent's network perspective"
}

type curlArgs struct {
	URL      string            `json:"url"`
	Method   string            `json:"method"`   // GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
	Headers  map[string]string `json:"headers"`  // custom headers
	Body     string            `json:"body"`     // request body for POST/PUT/PATCH
	Insecure bool              `json:"insecure"` // skip TLS verification (default: true)
	Timeout  int               `json:"timeout"`  // timeout in seconds (default: 30)
	MaxSize  int               `json:"max_size"` // max response body size in bytes (default: 1MB)
	Output   string            `json:"output"`   // "full" (headers+body), "body" (body only), "headers" (headers only)
}

const (
	defaultCurlTimeout = 30
	defaultMaxSize     = 1024 * 1024 // 1MB
)

func (c *CurlCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -url <URL> [-method GET] [-headers '{\"key\":\"val\"}'] [-body <data>]",
			Status:    "error",
			Completed: true,
		}
	}

	var args curlArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.URL == "" {
		return structs.CommandResult{
			Output:    "Error: url is required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Method == "" {
		args.Method = "GET"
	}
	args.Method = strings.ToUpper(args.Method)

	if args.Timeout <= 0 {
		args.Timeout = defaultCurlTimeout
	}

	if args.MaxSize <= 0 {
		args.MaxSize = defaultMaxSize
	}

	if args.Output == "" {
		args.Output = "full"
	}

	// Build HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // red team tool — TLS verification disabled by default
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(args.Timeout) * time.Second,
	}

	// Build request
	var bodyReader io.Reader
	if args.Body != "" {
		bodyReader = strings.NewReader(args.Body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(args.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, args.Method, args.URL, bodyReader)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating request: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Set custom headers
	for key, val := range args.Headers {
		req.Header.Set(key, val)
	}

	// Set default User-Agent if not provided
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error executing request: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer resp.Body.Close()

	// Read response body with size limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(args.MaxSize)+1))
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading response: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	truncated := len(body) > args.MaxSize
	if truncated {
		body = body[:args.MaxSize]
	}

	// Format output
	var sb strings.Builder

	switch args.Output {
	case "headers":
		sb.WriteString(fmt.Sprintf("HTTP/%d.%d %s\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status))
		for key, values := range resp.Header {
			for _, val := range values {
				sb.WriteString(fmt.Sprintf("%s: %s\n", key, val))
			}
		}

	case "body":
		sb.Write(body)
		if !strings.HasSuffix(string(body), "\n") {
			sb.WriteString("\n")
		}

	default: // "full"
		sb.WriteString(fmt.Sprintf("[*] %s %s\n", args.Method, args.URL))
		sb.WriteString(fmt.Sprintf("[*] Status: %s\n", resp.Status))
		sb.WriteString(fmt.Sprintf("[*] Content-Length: %d bytes", len(body)))
		if truncated {
			sb.WriteString(fmt.Sprintf(" (truncated to %d)", args.MaxSize))
		}
		sb.WriteString("\n")

		// Response headers
		sb.WriteString("\n--- Response Headers ---\n")
		for key, values := range resp.Header {
			for _, val := range values {
				sb.WriteString(fmt.Sprintf("%s: %s\n", key, val))
			}
		}

		// Response body
		sb.WriteString("\n--- Response Body ---\n")
		sb.Write(body)
		if !strings.HasSuffix(string(body), "\n") {
			sb.WriteString("\n")
		}
	}

	status := "success"
	if resp.StatusCode >= 400 {
		status = "error"
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}
