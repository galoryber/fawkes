package structs

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// --- Agent Tests ---

func TestAgent_UpdateSleepParams(t *testing.T) {
	agent := &Agent{SleepInterval: 10, Jitter: 10}

	agent.UpdateSleepParams(30, 50)
	if agent.SleepInterval != 30 {
		t.Errorf("SleepInterval = %d, want 30", agent.SleepInterval)
	}
	if agent.Jitter != 50 {
		t.Errorf("Jitter = %d, want 50", agent.Jitter)
	}
}

func TestAgent_UpdateSleepParams_Zero(t *testing.T) {
	agent := &Agent{SleepInterval: 10, Jitter: 10}
	agent.UpdateSleepParams(0, 0)
	if agent.SleepInterval != 0 {
		t.Errorf("SleepInterval = %d, want 0", agent.SleepInterval)
	}
	if agent.Jitter != 0 {
		t.Errorf("Jitter = %d, want 0", agent.Jitter)
	}
}

func TestAgent_JSON_Marshaling(t *testing.T) {
	agent := Agent{
		PayloadUUID:   "test-uuid-1234",
		Architecture:  "amd64",
		Host:          "DESKTOP-TEST",
		OS:            "windows",
		PID:           1234,
		ProcessName:   "agent.exe",
		SleepInterval: 10,
		Jitter:        20,
		User:          "testuser",
	}

	data, err := json.Marshal(agent)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Agent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.PayloadUUID != agent.PayloadUUID {
		t.Errorf("PayloadUUID = %q, want %q", decoded.PayloadUUID, agent.PayloadUUID)
	}
	if decoded.PID != agent.PID {
		t.Errorf("PID = %d, want %d", decoded.PID, agent.PID)
	}
	if decoded.SleepInterval != agent.SleepInterval {
		t.Errorf("SleepInterval = %d, want %d", decoded.SleepInterval, agent.SleepInterval)
	}
}

// --- Task Tests ---

func TestTask_StopFlags(t *testing.T) {
	task := Task{ID: "task-1", Command: "test"}

	if task.DidStop() {
		t.Error("DidStop() should be false initially")
	}
	if task.ShouldStop() {
		t.Error("ShouldStop() should be false initially")
	}

	task.SetStop()

	if !task.DidStop() {
		t.Error("DidStop() should be true after SetStop()")
	}
	if !task.ShouldStop() {
		t.Error("ShouldStop() should be true after SetStop()")
	}
}

func TestTask_NewResponse(t *testing.T) {
	task := Task{ID: "task-abc-123"}
	resp := task.NewResponse()

	if resp.TaskID != "task-abc-123" {
		t.Errorf("TaskID = %q, want %q", resp.TaskID, "task-abc-123")
	}
	if resp.UserOutput != "" {
		t.Errorf("UserOutput should be empty, got %q", resp.UserOutput)
	}
	if resp.Completed {
		t.Error("Completed should be false by default")
	}
}

func TestTask_JSON_Marshaling(t *testing.T) {
	task := Task{
		ID:      "task-1",
		Command: "whoami",
		Params:  `{"key": "value"}`,
	}

	data, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Task
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.ID != task.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, task.ID)
	}
	if decoded.Command != task.Command {
		t.Errorf("Command = %q, want %q", decoded.Command, task.Command)
	}
}

// --- Job Tests ---

func TestJob_SetGetFileTransfer(t *testing.T) {
	job := &Job{
		FileTransfers: make(map[string]chan json.RawMessage),
	}

	ch := make(chan json.RawMessage, 1)
	job.SetFileTransfer("test-key", ch)

	got, ok := job.GetFileTransfer("test-key")
	if !ok {
		t.Fatal("GetFileTransfer returned false for existing key")
	}
	if got != ch {
		t.Error("GetFileTransfer returned wrong channel")
	}
}

func TestJob_GetFileTransfer_Missing(t *testing.T) {
	job := &Job{
		FileTransfers: make(map[string]chan json.RawMessage),
	}

	_, ok := job.GetFileTransfer("nonexistent")
	if ok {
		t.Error("GetFileTransfer should return false for missing key")
	}
}

func TestJob_BroadcastFileTransfer(t *testing.T) {
	job := &Job{
		FileTransfers: make(map[string]chan json.RawMessage),
	}

	ch1 := make(chan json.RawMessage, 1)
	ch2 := make(chan json.RawMessage, 1)
	job.SetFileTransfer("key1", ch1)
	job.SetFileTransfer("key2", ch2)

	testData := json.RawMessage(`{"file_id":"abc"}`)
	job.BroadcastFileTransfer(testData)

	select {
	case msg := <-ch1:
		if string(msg) != string(testData) {
			t.Errorf("ch1 got %q, want %q", string(msg), string(testData))
		}
	case <-time.After(time.Second):
		t.Error("ch1 did not receive broadcast within timeout")
	}

	select {
	case msg := <-ch2:
		if string(msg) != string(testData) {
			t.Errorf("ch2 got %q, want %q", string(msg), string(testData))
		}
	case <-time.After(time.Second):
		t.Error("ch2 did not receive broadcast within timeout")
	}
}

func TestJob_BroadcastFileTransfer_FullChannel(t *testing.T) {
	job := &Job{
		FileTransfers: make(map[string]chan json.RawMessage),
	}

	// Unbuffered channel that nobody reads from — broadcast should timeout, not deadlock
	ch := make(chan json.RawMessage)
	job.SetFileTransfer("full", ch)

	done := make(chan bool)
	go func() {
		job.BroadcastFileTransfer(json.RawMessage(`{"test":"data"}`))
		done <- true
	}()

	select {
	case <-done:
		// BroadcastFileTransfer completed without deadlock
	case <-time.After(2 * time.Second):
		t.Fatal("BroadcastFileTransfer deadlocked on full channel")
	}
}

func TestJob_ConcurrentFileTransfer(t *testing.T) {
	job := &Job{
		FileTransfers: make(map[string]chan json.RawMessage),
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := "key-" + string(rune('A'+n%26))
			ch := make(chan json.RawMessage, 1)
			job.SetFileTransfer(key, ch)
			job.GetFileTransfer(key)
		}(i)
	}
	wg.Wait()
}

// --- Response Tests ---

func TestResponse_JSON_Marshaling(t *testing.T) {
	resp := Response{
		TaskID:     "task-1",
		UserOutput: "test output",
		Status:     "success",
		Completed:  true,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Response
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.TaskID != resp.TaskID {
		t.Errorf("TaskID = %q, want %q", decoded.TaskID, resp.TaskID)
	}
	if decoded.Completed != resp.Completed {
		t.Errorf("Completed = %v, want %v", decoded.Completed, resp.Completed)
	}
}

func TestResponse_WithUpload(t *testing.T) {
	resp := Response{
		TaskID: "task-1",
		Upload: &FileUploadMessage{
			ChunkSize: 512000,
			FileID:    "file-123",
			ChunkNum:  1,
			FullPath:  "/tmp/test.txt",
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Response
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Upload == nil {
		t.Fatal("Upload should not be nil")
	}
	if decoded.Upload.FileID != "file-123" {
		t.Errorf("Upload.FileID = %q, want %q", decoded.Upload.FileID, "file-123")
	}
}

func TestResponse_WithDownload(t *testing.T) {
	resp := Response{
		TaskID: "task-1",
		Download: &FileDownloadMessage{
			TotalChunks:  5,
			ChunkNum:     1,
			ChunkData:    "dGVzdA==",
			FullPath:     "/tmp/download.txt",
			FileID:       "file-456",
			IsScreenshot: false,
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Response
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Download == nil {
		t.Fatal("Download should not be nil")
	}
	if decoded.Download.TotalChunks != 5 {
		t.Errorf("TotalChunks = %d, want 5", decoded.Download.TotalChunks)
	}
}

func TestResponse_OmitsEmptyOptionalFields(t *testing.T) {
	resp := Response{
		TaskID:     "task-1",
		UserOutput: "output",
		Status:     "success",
		Completed:  true,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	jsonStr := string(data)
	if contains(jsonStr, "upload") {
		t.Error("JSON should not contain 'upload' when Upload is nil")
	}
	if contains(jsonStr, "download") {
		t.Error("JSON should not contain 'download' when Download is nil")
	}
}

// --- CheckinMessage Tests ---

func TestCheckinMessage_JSON(t *testing.T) {
	msg := CheckinMessage{
		Action:       "checkin",
		PayloadUUID:  "uuid-1234",
		User:         "testuser",
		Host:         "DESKTOP-TEST",
		PID:          5678,
		OS:           "windows",
		Architecture: "amd64",
		IPs:          []string{"192.168.1.100", "10.0.0.1"},
		ProcessName:  "agent.exe",
		Integrity:    3,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded CheckinMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Action != "checkin" {
		t.Errorf("Action = %q, want %q", decoded.Action, "checkin")
	}
	if len(decoded.IPs) != 2 {
		t.Errorf("IPs length = %d, want 2", len(decoded.IPs))
	}
	if decoded.IPs[0] != "192.168.1.100" {
		t.Errorf("IPs[0] = %q, want %q", decoded.IPs[0], "192.168.1.100")
	}
}

// --- TaskingMessage Tests ---

func TestTaskingMessage_JSON(t *testing.T) {
	msg := TaskingMessage{
		Action:      "get_tasking",
		TaskingSize: -1,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded TaskingMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.TaskingSize != -1 {
		t.Errorf("TaskingSize = %d, want -1", decoded.TaskingSize)
	}
}

func TestTaskingMessage_WithSocks(t *testing.T) {
	msg := TaskingMessage{
		Action:      "get_tasking",
		TaskingSize: -1,
		Socks: []SocksMsg{
			{ServerId: 1, Data: "dGVzdA==", Exit: false},
			{ServerId: 2, Data: "", Exit: true},
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded TaskingMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(decoded.Socks) != 2 {
		t.Fatalf("Socks length = %d, want 2", len(decoded.Socks))
	}
	if decoded.Socks[1].Exit != true {
		t.Error("Socks[1].Exit should be true")
	}
}

// --- PostResponseMessage Tests ---

func TestPostResponseMessage_JSON(t *testing.T) {
	msg := PostResponseMessage{
		Action: "post_response",
		Responses: []Response{
			{TaskID: "t1", UserOutput: "result", Status: "success", Completed: true},
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded PostResponseMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Action != "post_response" {
		t.Errorf("Action = %q, want %q", decoded.Action, "post_response")
	}
	if len(decoded.Responses) != 1 {
		t.Fatalf("Responses length = %d, want 1", len(decoded.Responses))
	}
}

// --- SocksMsg Tests ---

func TestSocksMsg_JSON(t *testing.T) {
	msg := SocksMsg{
		ServerId: 42,
		Data:     "aGVsbG8=",
		Exit:     false,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded SocksMsg
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.ServerId != 42 {
		t.Errorf("ServerId = %d, want 42", decoded.ServerId)
	}
}

// --- CommandResult Tests ---

func TestCommandResult_Fields(t *testing.T) {
	result := CommandResult{
		Output:    "command output",
		Status:    "success",
		Completed: true,
	}

	if result.Output != "command output" {
		t.Errorf("Output = %q, want %q", result.Output, "command output")
	}
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	if !result.Completed {
		t.Error("Completed should be true")
	}
}

// --- FileListing Tests ---

func TestFileListing_JSON(t *testing.T) {
	listing := FileListing{
		Host:       "DESKTOP-TEST",
		IsFile:     false,
		Name:       "testdir",
		ParentPath: "C:\\Users",
		Success:    true,
		Files: []FileListEntry{
			{
				Name:        "file.txt",
				FullName:    "C:\\Users\\testdir\\file.txt",
				IsFile:      true,
				Permissions: "-rw-r--r--",
				Size:        1024,
				Owner:       "testuser",
			},
		},
	}

	data, err := json.Marshal(listing)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded FileListing
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !decoded.Success {
		t.Error("Success should be true")
	}
	if len(decoded.Files) != 1 {
		t.Fatalf("Files length = %d, want 1", len(decoded.Files))
	}
	if decoded.Files[0].Size != 1024 {
		t.Errorf("Files[0].Size = %d, want 1024", decoded.Files[0].Size)
	}
}

func TestFileListing_EmptyFiles(t *testing.T) {
	listing := FileListing{
		Host:       "test",
		Name:       "empty",
		ParentPath: "/tmp",
		Success:    true,
	}

	data, err := json.Marshal(listing)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Files should be omitted when empty (omitempty)
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
	if _, exists := decoded["files"]; exists {
		t.Error("files should be omitted when nil (omitempty)")
	}
}

// helper
func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsImpl(s, substr)
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
