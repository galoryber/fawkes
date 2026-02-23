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

func TestCurlCommandName(t *testing.T) {
	cmd := &CurlCommand{}
	if cmd.Name() != "curl" {
		t.Errorf("expected 'curl', got '%s'", cmd.Name())
	}
}

func TestCurlCommandDescription(t *testing.T) {
	cmd := &CurlCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestCurlEmptyParams(t *testing.T) {
	cmd := &CurlCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestCurlBadJSON(t *testing.T) {
	cmd := &CurlCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestCurlMissingURL(t *testing.T) {
	cmd := &CurlCommand{}
	params, _ := json.Marshal(curlArgs{Method: "GET"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing URL, got %s", result.Status)
	}
}

func TestCurlGETRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("X-Test", "hello")
		fmt.Fprint(w, "test response body")
	}))
	defer server.Close()

	cmd := &CurlCommand{}
	params, _ := json.Marshal(curlArgs{URL: server.URL, Method: "GET"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "test response body") {
		t.Errorf("expected response body in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "200") {
		t.Errorf("expected 200 status in output, got: %s", result.Output)
	}
}

func TestCurlPOSTRequest(t *testing.T) {
	var receivedBody string
	var receivedContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		receivedContentType = r.Header.Get("Content-Type")
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		receivedBody = string(body)
		fmt.Fprint(w, "created")
	}))
	defer server.Close()

	cmd := &CurlCommand{}
	params, _ := json.Marshal(curlArgs{
		URL:    server.URL,
		Method: "POST",
		Body:   `{"key":"value"}`,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if receivedContentType != "application/json" {
		t.Errorf("expected application/json content type, got %s", receivedContentType)
	}
	if receivedBody != `{"key":"value"}` {
		t.Errorf("expected JSON body, got %s", receivedBody)
	}
}

func TestCurlCustomHeaders(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	cmd := &CurlCommand{}
	params, _ := json.Marshal(curlArgs{
		URL: server.URL,
		Headers: map[string]string{
			"Authorization": "Bearer mytoken123",
		},
	})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	if receivedAuth != "Bearer mytoken123" {
		t.Errorf("expected auth header, got %s", receivedAuth)
	}
}

func TestCurlOutputBodyOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "just the body")
	}))
	defer server.Close()

	cmd := &CurlCommand{}
	params, _ := json.Marshal(curlArgs{URL: server.URL, Output: "body"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	// Body-only output should not contain status or header labels
	if strings.Contains(result.Output, "[*]") {
		t.Errorf("body-only output should not contain metadata markers")
	}
	if !strings.Contains(result.Output, "just the body") {
		t.Errorf("expected body content, got: %s", result.Output)
	}
}

func TestCurlOutputHeadersOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "testval")
		fmt.Fprint(w, "this should not appear")
	}))
	defer server.Close()

	cmd := &CurlCommand{}
	params, _ := json.Marshal(curlArgs{URL: server.URL, Output: "headers"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "X-Custom: testval") {
		t.Errorf("expected custom header in output, got: %s", result.Output)
	}
	if strings.Contains(result.Output, "this should not appear") {
		t.Errorf("headers-only output should not contain body")
	}
}

func TestCurlErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "not found")
	}))
	defer server.Close()

	cmd := &CurlCommand{}
	params, _ := json.Marshal(curlArgs{URL: server.URL})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error for 404, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "not found") {
		t.Errorf("expected error body in output, got: %s", result.Output)
	}
}

func TestCurlMaxSizeTruncation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write more than 100 bytes
		fmt.Fprint(w, strings.Repeat("A", 200))
	}))
	defer server.Close()

	cmd := &CurlCommand{}
	params, _ := json.Marshal(curlArgs{URL: server.URL, MaxSize: 100})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "truncated") {
		t.Errorf("expected truncation notice in output, got: %s", result.Output)
	}
}

func TestCurlDefaultMethod(t *testing.T) {
	var receivedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	cmd := &CurlCommand{}
	params, _ := json.Marshal(curlArgs{URL: server.URL})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	if receivedMethod != "GET" {
		t.Errorf("expected default GET method, got %s", receivedMethod)
	}
}

func TestCurlBadURL(t *testing.T) {
	cmd := &CurlCommand{}
	params, _ := json.Marshal(curlArgs{URL: "not-a-url"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for bad URL, got %s", result.Status)
	}
}

func TestCurlDefaultUserAgent(t *testing.T) {
	var receivedUA string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get("User-Agent")
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	cmd := &CurlCommand{}
	params, _ := json.Marshal(curlArgs{URL: server.URL})
	_ = cmd.Execute(structs.Task{Params: string(params)})

	if !strings.Contains(receivedUA, "Mozilla") {
		t.Errorf("expected Mozilla user agent, got %s", receivedUA)
	}
}
