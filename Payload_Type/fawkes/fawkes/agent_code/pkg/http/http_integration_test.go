package http

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

// Standard 36-char UUID for tests (matches Mythic format)
const testPayloadUUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
const testCallbackUUID = "11111111-2222-3333-4444-555555555555"

// --- makeRequest Tests ---

func TestMakeRequest_BasicPOST(t *testing.T) {
	var receivedBody string
	var receivedUA string
	var receivedContentType string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get("User-Agent")
		receivedContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:   ts.URL,
		UserAgent: "FawkesTest/1.0",
		client:    ts.Client(),
	}

	resp, err := profile.makeRequest("POST", "/test", []byte("hello"))
	if err != nil {
		t.Fatalf("makeRequest failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if receivedBody != "hello" {
		t.Errorf("body = %q, want %q", receivedBody, "hello")
	}
	if receivedUA != "FawkesTest/1.0" {
		t.Errorf("User-Agent = %q, want %q", receivedUA, "FawkesTest/1.0")
	}
	if receivedContentType != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", receivedContentType, "text/plain")
	}
}

func TestMakeRequest_HostHeaderOverride(t *testing.T) {
	var receivedHost string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:    ts.URL,
		UserAgent:  "Test/1.0",
		HostHeader: "fronted.example.com",
		client:     ts.Client(),
	}

	resp, err := profile.makeRequest("POST", "/test", []byte("data"))
	if err != nil {
		t.Fatalf("makeRequest failed: %v", err)
	}
	defer resp.Body.Close()

	if receivedHost != "fronted.example.com" {
		t.Errorf("Host = %q, want %q", receivedHost, "fronted.example.com")
	}
}

func TestMakeRequest_URLJoining(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		path     string
		wantPath string
	}{
		{"both have slash", "http://host/", "/path", "/path"},
		{"neither has slash", "http://host", "path", "/path"},
		{"base has slash", "http://host/", "path", "/path"},
		{"path has slash", "http://host", "/path", "/path"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var receivedPath string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			}))
			defer ts.Close()

			// Replace host in baseURL with test server
			baseURL := ts.URL
			if strings.HasSuffix(tc.baseURL, "/") {
				baseURL += "/"
			}

			profile := &HTTPProfile{
				BaseURL:   baseURL,
				UserAgent: "Test/1.0",
				client:    ts.Client(),
			}

			resp, err := profile.makeRequest("POST", tc.path, nil)
			if err != nil {
				t.Fatalf("makeRequest failed: %v", err)
			}
			defer resp.Body.Close()

			if receivedPath != tc.wantPath {
				t.Errorf("path = %q, want %q", receivedPath, tc.wantPath)
			}
		})
	}
}

func TestMakeRequest_NilBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Errorf("expected empty body, got %d bytes", len(body))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:   ts.URL,
		UserAgent: "Test/1.0",
		client:    ts.Client(),
	}

	resp, err := profile.makeRequest("GET", "/test", nil)
	if err != nil {
		t.Fatalf("makeRequest failed: %v", err)
	}
	resp.Body.Close()
}

func TestMakeRequest_ServerDown(t *testing.T) {
	profile := &HTTPProfile{
		BaseURL:   "http://127.0.0.1:1", // Nothing listening on port 1
		UserAgent: "Test/1.0",
		client:    &http.Client{},
	}

	_, err := profile.makeRequest("POST", "/test", []byte("data"))
	if err == nil {
		t.Error("makeRequest should fail when server is down")
	}
}

// --- Checkin Tests ---

func TestCheckin_Success_Plaintext(t *testing.T) {
	callbackUUID := "callback-uuid-from-mythic"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read and decode the base64 body
		body, _ := io.ReadAll(r.Body)
		decoded, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil {
			t.Errorf("failed to decode request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// First 36 bytes are the UUID, rest is JSON
		if len(decoded) < 36 {
			t.Errorf("decoded body too short: %d bytes", len(decoded))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify the JSON payload
		var checkinMsg structs.CheckinMessage
		if err := json.Unmarshal(decoded[36:], &checkinMsg); err != nil {
			t.Errorf("failed to unmarshal checkin message: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if checkinMsg.Action != "checkin" {
			t.Errorf("action = %q, want %q", checkinMsg.Action, "checkin")
		}

		// Return checkin response with callback UUID
		resp := map[string]interface{}{
			"action": "checkin",
			"id":     callbackUUID,
			"status": "success",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID:  testPayloadUUID,
		User:         "testuser",
		Host:         "testhost",
		PID:          1234,
		OS:           "windows",
		Architecture: "amd64",
		InternalIP:   "192.168.1.100",
	}

	err := profile.Checkin(agent)
	if err != nil {
		t.Fatalf("Checkin failed: %v", err)
	}

	if profile.CallbackUUID != callbackUUID {
		t.Errorf("CallbackUUID = %q, want %q", profile.CallbackUUID, callbackUUID)
	}
}

func TestCheckin_Success_UUIDKey(t *testing.T) {
	// Test that "uuid" key is also accepted (not just "id")
	callbackUUID := "callback-uuid-via-uuid-key"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"action": "checkin",
			"uuid":   callbackUUID,
			"status": "success",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	err := profile.Checkin(agent)
	if err != nil {
		t.Fatalf("Checkin failed: %v", err)
	}

	if profile.CallbackUUID != callbackUUID {
		t.Errorf("CallbackUUID = %q, want %q", profile.CallbackUUID, callbackUUID)
	}
}

func TestCheckin_NoCallbackUUID_FallsBackToPayloadUUID(t *testing.T) {
	// Response has neither "id" nor "uuid" — should fall back to payload UUID
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"action": "checkin",
			"status": "success",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	err := profile.Checkin(agent)
	if err != nil {
		t.Fatalf("Checkin failed: %v", err)
	}

	if profile.CallbackUUID != agent.PayloadUUID {
		t.Errorf("CallbackUUID = %q, want payload UUID %q", profile.CallbackUUID, agent.PayloadUUID)
	}
}

func TestCheckin_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	err := profile.Checkin(agent)
	if err == nil {
		t.Error("Checkin should fail with server error")
	}
}

func TestCheckin_InvalidJSONResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not valid json"))
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	err := profile.Checkin(agent)
	if err == nil {
		t.Error("Checkin should fail with invalid JSON response")
	}
}

func TestCheckin_WithEncryption(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)
	callbackUUID := "encrypted-callback-uuid"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Build an encrypted response
		profile := &HTTPProfile{EncryptionKey: keyB64}

		resp := map[string]interface{}{
			"action": "checkin",
			"id":     callbackUUID,
			"status": "success",
		}
		respJSON, _ := json.Marshal(resp)

		// Encrypt the response
		encrypted := profile.encryptMessage(respJSON)

		// Prepend a 36-byte UUID (the callback UUID padded/truncated)
		fakeUUID := []byte("12345678-1234-1234-1234-123456789012")
		withUUID := append(fakeUUID, encrypted...)

		// Base64 encode the whole thing
		encoded := base64.StdEncoding.EncodeToString(withUUID)
		w.Write([]byte(encoded))
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:       ts.URL,
		UserAgent:     "Test/1.0",
		EncryptionKey: keyB64,
		PostEndpoint:  "/post",
		client:        ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	err := profile.Checkin(agent)
	if err != nil {
		t.Fatalf("Checkin with encryption failed: %v", err)
	}

	if profile.CallbackUUID != callbackUUID {
		t.Errorf("CallbackUUID = %q, want %q", profile.CallbackUUID, callbackUUID)
	}
}

func TestCheckin_EncryptedBadBase64Response(t *testing.T) {
	key := make([]byte, 32)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not-valid-base64!!!"))
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:       ts.URL,
		UserAgent:     "Test/1.0",
		EncryptionKey: keyB64,
		PostEndpoint:  "/post",
		client:        ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	err := profile.Checkin(agent)
	if err == nil {
		t.Error("Checkin should fail with bad base64 response")
	}
}

// --- GetTasking Tests ---

func TestGetTasking_Success_Plaintext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"action": "get_tasking",
			"tasks": []map[string]interface{}{
				{
					"id":         "task-001",
					"command":    "whoami",
					"parameters": "",
				},
				{
					"id":         "task-002",
					"command":    "ls",
					"parameters": "/tmp",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	tasks, socks, err := profile.GetTasking(agent, nil)
	if err != nil {
		t.Fatalf("GetTasking failed: %v", err)
	}

	if len(tasks) != 2 {
		t.Fatalf("got %d tasks, want 2", len(tasks))
	}

	if tasks[0].ID != "task-001" || tasks[0].Command != "whoami" {
		t.Errorf("task[0] = {ID:%q, Command:%q}, want {task-001, whoami}", tasks[0].ID, tasks[0].Command)
	}
	if tasks[1].ID != "task-002" || tasks[1].Command != "ls" || tasks[1].Params != "/tmp" {
		t.Errorf("task[1] = {ID:%q, Command:%q, Params:%q}, want {task-002, ls, /tmp}", tasks[1].ID, tasks[1].Command, tasks[1].Params)
	}

	if len(socks) != 0 {
		t.Errorf("got %d socks messages, want 0", len(socks))
	}
}

func TestGetTasking_EmptyTasks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"action": "get_tasking",
			"tasks":  []interface{}{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	tasks, _, err := profile.GetTasking(agent, nil)
	if err != nil {
		t.Fatalf("GetTasking failed: %v", err)
	}

	if len(tasks) != 0 {
		t.Errorf("got %d tasks, want 0", len(tasks))
	}
}

func TestGetTasking_WithSocks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"action": "get_tasking",
			"tasks":  []interface{}{},
			"socks": []map[string]interface{}{
				{
					"server_id": 42,
					"data":      base64.StdEncoding.EncodeToString([]byte("socks-data")),
					"exit":      false,
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	_, socks, err := profile.GetTasking(agent, nil)
	if err != nil {
		t.Fatalf("GetTasking failed: %v", err)
	}

	if len(socks) != 1 {
		t.Fatalf("got %d socks messages, want 1", len(socks))
	}

	if socks[0].ServerId != 42 {
		t.Errorf("socks[0].ServerId = %d, want 42", socks[0].ServerId)
	}
}

func TestGetTasking_NonJSONResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	// Non-JSON response should return empty tasks, not error
	tasks, _, err := profile.GetTasking(agent, nil)
	if err != nil {
		t.Fatalf("GetTasking should not error on non-JSON: %v", err)
	}
	if len(tasks) != 0 {
		t.Errorf("got %d tasks, want 0 for non-JSON response", len(tasks))
	}
}

func TestGetTasking_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	_, _, err := profile.GetTasking(agent, nil)
	if err == nil {
		t.Error("GetTasking should fail with server error")
	}
}

func TestGetTasking_WithEncryption(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profile := &HTTPProfile{EncryptionKey: keyB64}

		resp := map[string]interface{}{
			"action": "get_tasking",
			"tasks": []map[string]interface{}{
				{
					"id":         "enc-task-001",
					"command":    "pwd",
					"parameters": "",
				},
			},
		}
		respJSON, _ := json.Marshal(resp)
		encrypted := profile.encryptMessage(respJSON)

		fakeUUID := []byte("12345678-1234-1234-1234-123456789012")
		withUUID := append(fakeUUID, encrypted...)
		encoded := base64.StdEncoding.EncodeToString(withUUID)
		w.Write([]byte(encoded))
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:       ts.URL,
		UserAgent:     "Test/1.0",
		EncryptionKey: keyB64,
		PostEndpoint:  "/post",
		client:        ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	tasks, _, err := profile.GetTasking(agent, nil)
	if err != nil {
		t.Fatalf("GetTasking with encryption failed: %v", err)
	}

	if len(tasks) != 1 {
		t.Fatalf("got %d tasks, want 1", len(tasks))
	}
	if tasks[0].Command != "pwd" {
		t.Errorf("task command = %q, want %q", tasks[0].Command, "pwd")
	}
}

func TestGetTasking_UsesCallbackUUID(t *testing.T) {
	var receivedBody string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		resp := map[string]interface{}{
			"action": "get_tasking",
			"tasks":  []interface{}{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	callbackUUID := "cccccccc-dddd-eeee-ffff-000000000001"

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		CallbackUUID: callbackUUID,
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	_, _, err := profile.GetTasking(agent, nil)
	if err != nil {
		t.Fatalf("GetTasking failed: %v", err)
	}

	// Decode the body and verify the callback UUID is used (first 36 bytes of decoded data)
	decoded, err := base64.StdEncoding.DecodeString(receivedBody)
	if err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}

	if len(decoded) < 36 {
		t.Fatalf("decoded body too short: %d bytes", len(decoded))
	}

	sentUUID := string(decoded[:len(callbackUUID)])
	if sentUUID != callbackUUID {
		t.Errorf("sent UUID = %q, want callback UUID %q", sentUUID, callbackUUID)
	}
}

func TestGetTasking_SendsOutboundSocks(t *testing.T) {
	var receivedJSON map[string]interface{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		decoded, _ := base64.StdEncoding.DecodeString(string(body))

		// Skip the 36-byte UUID prefix
		if len(decoded) > 36 {
			json.Unmarshal(decoded[36:], &receivedJSON)
		}

		resp := map[string]interface{}{
			"action": "get_tasking",
			"tasks":  []interface{}{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	outboundSocks := []structs.SocksMsg{
		{ServerId: 1, Data: "dGVzdA==", Exit: false},
	}

	_, _, err := profile.GetTasking(agent, outboundSocks)
	if err != nil {
		t.Fatalf("GetTasking failed: %v", err)
	}

	// Verify the outbound SOCKS data was included in the request
	if receivedJSON == nil {
		t.Fatal("server did not receive JSON body")
	}

	socksData, exists := receivedJSON["socks"]
	if !exists {
		t.Error("request body should contain 'socks' key")
	}

	socksArray, ok := socksData.([]interface{})
	if !ok {
		t.Errorf("socks should be array, got %T", socksData)
	} else if len(socksArray) != 1 {
		t.Errorf("got %d socks messages, want 1", len(socksArray))
	}
}

// --- PostResponse Tests ---

func TestPostResponse_Success_Plaintext(t *testing.T) {
	var receivedJSON map[string]interface{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		decoded, _ := base64.StdEncoding.DecodeString(string(body))

		// Skip UUID prefix
		if len(decoded) > 36 {
			json.Unmarshal(decoded[36:], &receivedJSON)
		}

		resp := map[string]interface{}{
			"action":    "post_response",
			"responses": []interface{}{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		CallbackUUID: testCallbackUUID,
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	response := structs.Response{
		TaskID:     "task-001",
		UserOutput: "command output here",
		Status:     "success",
		Completed:  true,
	}

	result, err := profile.PostResponse(response, agent, nil)
	if err != nil {
		t.Fatalf("PostResponse failed: %v", err)
	}

	if result == nil {
		t.Error("PostResponse should return non-nil result")
	}

	// Verify the request had post_response action
	if receivedJSON == nil {
		t.Fatal("server did not receive JSON body")
	}

	action, _ := receivedJSON["action"].(string)
	if action != "post_response" {
		t.Errorf("action = %q, want %q", action, "post_response")
	}
}

func TestPostResponse_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	response := structs.Response{
		TaskID: "task-001",
		Status: "success",
	}

	_, err := profile.PostResponse(response, agent, nil)
	if err == nil {
		t.Error("PostResponse should fail with server error")
	}
}

func TestPostResponse_WithSocks(t *testing.T) {
	var receivedJSON map[string]interface{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		decoded, _ := base64.StdEncoding.DecodeString(string(body))

		if len(decoded) > 36 {
			json.Unmarshal(decoded[36:], &receivedJSON)
		}

		resp := map[string]interface{}{"action": "post_response"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	response := structs.Response{
		TaskID: "task-001",
		Status: "success",
	}

	socksData := []structs.SocksMsg{
		{ServerId: 99, Data: "c29ja3M=", Exit: true},
	}

	_, err := profile.PostResponse(response, agent, socksData)
	if err != nil {
		t.Fatalf("PostResponse failed: %v", err)
	}

	if receivedJSON == nil {
		t.Fatal("server did not receive JSON body")
	}

	if _, exists := receivedJSON["socks"]; !exists {
		t.Error("request body should contain 'socks' key")
	}
}

func TestPostResponse_WithEncryption(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profile := &HTTPProfile{EncryptionKey: keyB64}

		resp := map[string]interface{}{
			"action":    "post_response",
			"responses": []interface{}{},
		}
		respJSON, _ := json.Marshal(resp)
		encrypted := profile.encryptMessage(respJSON)

		fakeUUID := []byte("12345678-1234-1234-1234-123456789012")
		withUUID := append(fakeUUID, encrypted...)
		encoded := base64.StdEncoding.EncodeToString(withUUID)
		w.Write([]byte(encoded))
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:       ts.URL,
		UserAgent:     "Test/1.0",
		EncryptionKey: keyB64,
		PostEndpoint:  "/post",
		CallbackUUID:  testCallbackUUID,
		client:        ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	response := structs.Response{
		TaskID:     "task-001",
		UserOutput: "encrypted output",
		Status:     "success",
		Completed:  true,
	}

	result, err := profile.PostResponse(response, agent, nil)
	if err != nil {
		t.Fatalf("PostResponse with encryption failed: %v", err)
	}

	// Verify the decrypted response is valid JSON
	var parsedResult map[string]interface{}
	if err := json.Unmarshal(result, &parsedResult); err != nil {
		t.Errorf("failed to parse decrypted PostResponse result: %v", err)
	}
}

func TestPostResponse_UsesCallbackUUID(t *testing.T) {
	var receivedBody string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		resp := map[string]interface{}{"action": "post_response"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	callbackUUID := "cccccccc-dddd-eeee-ffff-000000000002"

	profile := &HTTPProfile{
		BaseURL:      ts.URL,
		UserAgent:    "Test/1.0",
		PostEndpoint: "/post",
		CallbackUUID: callbackUUID,
		client:       ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	response := structs.Response{
		TaskID: "task-001",
		Status: "success",
	}

	_, err := profile.PostResponse(response, agent, nil)
	if err != nil {
		t.Fatalf("PostResponse failed: %v", err)
	}

	// Verify the callback UUID is used
	decoded, err := base64.StdEncoding.DecodeString(receivedBody)
	if err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}

	if len(decoded) < len(callbackUUID) {
		t.Fatalf("decoded body too short: %d bytes", len(decoded))
	}

	sentUUID := string(decoded[:len(callbackUUID)])
	if sentUUID != callbackUUID {
		t.Errorf("sent UUID = %q, want callback UUID %q", sentUUID, callbackUUID)
	}
}

// --- Alternative HMAC Method Test ---

func TestDecryptResponse_AlternativeHMAC(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	profile := &HTTPProfile{
		EncryptionKey: keyB64,
	}

	// Build a message that uses the alternative HMAC format:
	// HMAC over IV + ciphertext only (not UUID + IV + ciphertext)
	// The standard encryptMessage() produces HMAC over IV + ciphertext,
	// while decryptResponse first tries HMAC over UUID + IV + ciphertext.
	// So we need to craft a message where the primary HMAC check fails
	// but the alternative (IV + ciphertext) succeeds.

	// Use encryptMessage to produce correctly encrypted data
	original := []byte(`{"test":"data"}`)
	encrypted := profile.encryptMessage(original)

	// encrypted = IV + ciphertext + HMAC(key, IV+ciphertext)
	// decryptResponse expects: UUID(36) + IV + ciphertext + HMAC
	// Primary check: HMAC(key, UUID+IV+ciphertext) — this will FAIL because
	//   encryptMessage computes HMAC(key, IV+ciphertext) without UUID
	// Alternative check: HMAC(key, IV+ciphertext) — this should SUCCEED

	fakeUUID := []byte("12345678-1234-1234-1234-123456789012")
	withUUID := append(fakeUUID, encrypted...)

	// This should work because our encryptMessage HMAC is over IV+ciphertext
	// and decryptResponse tries that as the alternative method
	decrypted, err := profile.decryptResponse(withUUID)
	if err != nil {
		t.Fatalf("decryptResponse with alternative HMAC failed: %v", err)
	}

	if string(decrypted) != string(original) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(original))
	}
}

// --- GetTasking Encrypted with Bad Decryption ---

func TestGetTasking_EncryptedBadDecryption(t *testing.T) {
	key := make([]byte, 32)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return data that can't be base64-decoded
		w.Write([]byte("not-base64!!!"))
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:       ts.URL,
		UserAgent:     "Test/1.0",
		EncryptionKey: keyB64,
		PostEndpoint:  "/post",
		client:        ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	_, _, err := profile.GetTasking(agent, nil)
	if err == nil {
		t.Error("GetTasking should fail with bad base64 encrypted response")
	}
}

// --- PostResponse Encrypted with Bad Decryption ---

func TestPostResponse_EncryptedBadBase64(t *testing.T) {
	key := make([]byte, 32)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not-base64!!!"))
	}))
	defer ts.Close()

	profile := &HTTPProfile{
		BaseURL:       ts.URL,
		UserAgent:     "Test/1.0",
		EncryptionKey: keyB64,
		PostEndpoint:  "/post",
		CallbackUUID:  testCallbackUUID,
		client:        ts.Client(),
	}

	agent := &structs.Agent{
		PayloadUUID: testPayloadUUID,
	}

	response := structs.Response{
		TaskID: "task-001",
		Status: "success",
	}

	_, err := profile.PostResponse(response, agent, nil)
	if err == nil {
		t.Error("PostResponse should fail with bad base64 encrypted response")
	}
}
