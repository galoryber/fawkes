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

// --- NewTask Tests ---

func TestNewTask_Fields(t *testing.T) {
	task := NewTask("task-123", "whoami", `{"key":"val"}`)
	if task.ID != "task-123" {
		t.Errorf("ID = %q, want %q", task.ID, "task-123")
	}
	if task.Command != "whoami" {
		t.Errorf("Command = %q, want %q", task.Command, "whoami")
	}
	if task.Params != `{"key":"val"}` {
		t.Errorf("Params = %q, want %q", task.Params, `{"key":"val"}`)
	}
}

func TestNewTask_StopFlagInitialized(t *testing.T) {
	task := NewTask("task-456", "ls", "")
	// stopped pointer should be initialized (not nil)
	if task.ShouldStop() {
		t.Error("ShouldStop() should be false for new task")
	}
	task.SetStop()
	if !task.ShouldStop() {
		t.Error("ShouldStop() should be true after SetStop()")
	}
}

func TestNewTask_CopiesShareStopFlag(t *testing.T) {
	task := NewTask("task-789", "cat", "")
	taskCopy := task // Value copy
	if taskCopy.ShouldStop() {
		t.Error("Copy should not be stopped initially")
	}
	task.SetStop()
	if !taskCopy.ShouldStop() {
		t.Error("Copy should see stop flag set on original (shared pointer)")
	}
}

// --- Working Hours Tests ---

func TestParseWorkingHoursTime(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{"09:00", 540, false},
		{"17:00", 1020, false},
		{"00:00", 0, false},
		{"23:59", 1439, false},
		{"12:30", 750, false},
		{"", 0, false},
		{"9:00", 540, false},  // single digit hour
		{"09:5", 545, false},  // single digit minute (valid, 09:05)
		{"25:00", 0, true},    // hour out of range
		{"09:60", 0, true},    // minute out of range
		{"09", 0, true},       // missing colon
		{"abc:def", 0, true},  // non-numeric
		{"09:00:00", 0, true}, // too many parts
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseWorkingHoursTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseWorkingHoursTime(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseWorkingHoursTime(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseWorkingDays(t *testing.T) {
	tests := []struct {
		input   string
		want    []int
		wantErr bool
	}{
		{"1,2,3,4,5", []int{1, 2, 3, 4, 5}, false},
		{"1,3,5", []int{1, 3, 5}, false},
		{"7", []int{7}, false},
		{"", nil, false},
		{"0", nil, true},                       // 0 out of range
		{"8", nil, true},                       // 8 out of range
		{"1,abc", nil, true},                   // non-numeric
		{" 1 , 2 , 3 ", []int{1, 2, 3}, false}, // spaces
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseWorkingDays(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseWorkingDays(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("ParseWorkingDays(%q) len = %d, want %d", tt.input, len(got), len(tt.want))
					return
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("ParseWorkingDays(%q)[%d] = %d, want %d", tt.input, i, got[i], tt.want[i])
					}
				}
			}
		})
	}
}

func TestFormatWorkingHoursTime(t *testing.T) {
	tests := []struct {
		minutes int
		want    string
	}{
		{540, "09:00"},
		{1020, "17:00"},
		{0, "00:00"},
		{1439, "23:59"},
		{750, "12:30"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatWorkingHoursTime(tt.minutes)
			if got != tt.want {
				t.Errorf("FormatWorkingHoursTime(%d) = %q, want %q", tt.minutes, got, tt.want)
			}
		})
	}
}

func TestAgent_WorkingHoursEnabled(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		agent := &Agent{}
		if agent.WorkingHoursEnabled() {
			t.Error("WorkingHoursEnabled() should be false with zero values")
		}
	})
	t.Run("enabled with start only", func(t *testing.T) {
		agent := &Agent{WorkingHoursStart: 540}
		if !agent.WorkingHoursEnabled() {
			t.Error("WorkingHoursEnabled() should be true with non-zero start")
		}
	})
	t.Run("enabled with end only", func(t *testing.T) {
		agent := &Agent{WorkingHoursEnd: 1020}
		if !agent.WorkingHoursEnabled() {
			t.Error("WorkingHoursEnabled() should be true with non-zero end")
		}
	})
	t.Run("enabled with both", func(t *testing.T) {
		agent := &Agent{WorkingHoursStart: 540, WorkingHoursEnd: 1020}
		if !agent.WorkingHoursEnabled() {
			t.Error("WorkingHoursEnabled() should be true with both set")
		}
	})
}

func TestAgent_UpdateWorkingHours(t *testing.T) {
	agent := &Agent{}
	agent.UpdateWorkingHours(540, 1020, []int{1, 2, 3, 4, 5})
	if agent.WorkingHoursStart != 540 {
		t.Errorf("WorkingHoursStart = %d, want 540", agent.WorkingHoursStart)
	}
	if agent.WorkingHoursEnd != 1020 {
		t.Errorf("WorkingHoursEnd = %d, want 1020", agent.WorkingHoursEnd)
	}
	if len(agent.WorkingDays) != 5 {
		t.Errorf("WorkingDays len = %d, want 5", len(agent.WorkingDays))
	}
}

func TestAgent_IsWithinWorkingHours(t *testing.T) {
	// Helper to create a time on a specific weekday at HH:MM
	makeTime := func(weekday time.Weekday, hour, minute int) time.Time {
		// 2026-02-16 is a Monday
		// Monday=16, Tuesday=17, ..., Sunday=22
		day := 16 + int(weekday) - 1
		if weekday == time.Sunday {
			day = 22
		}
		return time.Date(2026, 2, day, hour, minute, 0, 0, time.Local)
	}

	t.Run("disabled - always within", func(t *testing.T) {
		agent := &Agent{} // no working hours
		if !agent.IsWithinWorkingHours(makeTime(time.Monday, 3, 0)) {
			t.Error("should be within hours when disabled")
		}
	})

	t.Run("normal range - within", func(t *testing.T) {
		agent := &Agent{WorkingHoursStart: 540, WorkingHoursEnd: 1020} // 09:00-17:00
		if !agent.IsWithinWorkingHours(makeTime(time.Monday, 12, 0)) {
			t.Error("12:00 should be within 09:00-17:00")
		}
	})

	t.Run("normal range - before start", func(t *testing.T) {
		agent := &Agent{WorkingHoursStart: 540, WorkingHoursEnd: 1020}
		if agent.IsWithinWorkingHours(makeTime(time.Monday, 6, 0)) {
			t.Error("06:00 should be outside 09:00-17:00")
		}
	})

	t.Run("normal range - after end", func(t *testing.T) {
		agent := &Agent{WorkingHoursStart: 540, WorkingHoursEnd: 1020}
		if agent.IsWithinWorkingHours(makeTime(time.Monday, 20, 0)) {
			t.Error("20:00 should be outside 09:00-17:00")
		}
	})

	t.Run("normal range - at start boundary", func(t *testing.T) {
		agent := &Agent{WorkingHoursStart: 540, WorkingHoursEnd: 1020}
		if !agent.IsWithinWorkingHours(makeTime(time.Monday, 9, 0)) {
			t.Error("09:00 should be within (start is inclusive)")
		}
	})

	t.Run("normal range - at end boundary", func(t *testing.T) {
		agent := &Agent{WorkingHoursStart: 540, WorkingHoursEnd: 1020}
		if agent.IsWithinWorkingHours(makeTime(time.Monday, 17, 0)) {
			t.Error("17:00 should be outside (end is exclusive)")
		}
	})

	t.Run("overnight range - within late", func(t *testing.T) {
		agent := &Agent{WorkingHoursStart: 1320, WorkingHoursEnd: 360} // 22:00-06:00
		if !agent.IsWithinWorkingHours(makeTime(time.Monday, 23, 0)) {
			t.Error("23:00 should be within 22:00-06:00")
		}
	})

	t.Run("overnight range - within early", func(t *testing.T) {
		agent := &Agent{WorkingHoursStart: 1320, WorkingHoursEnd: 360} // 22:00-06:00
		if !agent.IsWithinWorkingHours(makeTime(time.Monday, 3, 0)) {
			t.Error("03:00 should be within 22:00-06:00")
		}
	})

	t.Run("overnight range - outside midday", func(t *testing.T) {
		agent := &Agent{WorkingHoursStart: 1320, WorkingHoursEnd: 360} // 22:00-06:00
		if agent.IsWithinWorkingHours(makeTime(time.Monday, 12, 0)) {
			t.Error("12:00 should be outside 22:00-06:00")
		}
	})

	t.Run("weekday restriction - allowed day", func(t *testing.T) {
		agent := &Agent{
			WorkingHoursStart: 540,
			WorkingHoursEnd:   1020,
			WorkingDays:       []int{1, 2, 3, 4, 5}, // Mon-Fri
		}
		if !agent.IsWithinWorkingHours(makeTime(time.Wednesday, 12, 0)) {
			t.Error("Wednesday 12:00 should be within Mon-Fri 09:00-17:00")
		}
	})

	t.Run("weekday restriction - disallowed day", func(t *testing.T) {
		agent := &Agent{
			WorkingHoursStart: 540,
			WorkingHoursEnd:   1020,
			WorkingDays:       []int{1, 2, 3, 4, 5}, // Mon-Fri
		}
		if agent.IsWithinWorkingHours(makeTime(time.Saturday, 12, 0)) {
			t.Error("Saturday 12:00 should be outside Mon-Fri")
		}
	})

	t.Run("weekday restriction - Sunday", func(t *testing.T) {
		agent := &Agent{
			WorkingHoursStart: 540,
			WorkingHoursEnd:   1020,
			WorkingDays:       []int{1, 2, 3, 4, 5}, // Mon-Fri
		}
		if agent.IsWithinWorkingHours(makeTime(time.Sunday, 12, 0)) {
			t.Error("Sunday 12:00 should be outside Mon-Fri")
		}
	})

	t.Run("weekday restriction - Sunday allowed", func(t *testing.T) {
		agent := &Agent{
			WorkingHoursStart: 540,
			WorkingHoursEnd:   1020,
			WorkingDays:       []int{7}, // Sun only
		}
		if !agent.IsWithinWorkingHours(makeTime(time.Sunday, 12, 0)) {
			t.Error("Sunday 12:00 should be within Sun-only 09:00-17:00")
		}
	})
}

func TestAgent_MinutesUntilWorkingHours(t *testing.T) {
	makeTime := func(weekday time.Weekday, hour, minute int) time.Time {
		day := 16 + int(weekday) - 1
		if weekday == time.Sunday {
			day = 22
		}
		return time.Date(2026, 2, day, hour, minute, 0, 0, time.Local)
	}

	t.Run("already within hours", func(t *testing.T) {
		agent := &Agent{WorkingHoursStart: 540, WorkingHoursEnd: 1020}
		got := agent.MinutesUntilWorkingHours(makeTime(time.Monday, 12, 0))
		if got != 0 {
			t.Errorf("expected 0, got %d", got)
		}
	})

	t.Run("disabled - always 0", func(t *testing.T) {
		agent := &Agent{}
		got := agent.MinutesUntilWorkingHours(makeTime(time.Monday, 3, 0))
		if got != 0 {
			t.Errorf("expected 0 for disabled, got %d", got)
		}
	})

	t.Run("before start same day", func(t *testing.T) {
		agent := &Agent{WorkingHoursStart: 540, WorkingHoursEnd: 1020}     // 09:00-17:00
		got := agent.MinutesUntilWorkingHours(makeTime(time.Monday, 6, 0)) // 06:00
		if got != 180 {                                                    // 3 hours
			t.Errorf("expected 180 minutes, got %d", got)
		}
	})

	t.Run("after end - wait until tomorrow", func(t *testing.T) {
		agent := &Agent{WorkingHoursStart: 540, WorkingHoursEnd: 1020}      // 09:00-17:00
		got := agent.MinutesUntilWorkingHours(makeTime(time.Monday, 20, 0)) // 20:00
		// 4 hours to midnight + 9 hours to 09:00 = 13 hours = 780 minutes
		if got != 780 {
			t.Errorf("expected 780 minutes, got %d", got)
		}
	})

	t.Run("weekday skip to next workday", func(t *testing.T) {
		agent := &Agent{
			WorkingHoursStart: 540,
			WorkingHoursEnd:   1020,
			WorkingDays:       []int{1, 2, 3, 4, 5}, // Mon-Fri
		}
		// Saturday 12:00 → need to wait until Monday 09:00
		got := agent.MinutesUntilWorkingHours(makeTime(time.Saturday, 12, 0))
		// 12 hours to midnight + 24 hours (Sunday) + 9 hours to 09:00 = 45 hours = 2700 minutes
		expected := (1440 - 720) + 1440 + 540 // 720 + 1440 + 540 = 2700
		if got != expected {
			t.Errorf("expected %d minutes (Sat 12:00 → Mon 09:00), got %d", expected, got)
		}
	})

	t.Run("Friday evening to Monday morning", func(t *testing.T) {
		agent := &Agent{
			WorkingHoursStart: 540,
			WorkingHoursEnd:   1020,
			WorkingDays:       []int{1, 2, 3, 4, 5}, // Mon-Fri
		}
		// Friday 18:00 → Monday 09:00
		got := agent.MinutesUntilWorkingHours(makeTime(time.Friday, 18, 0))
		// 6 hours to midnight + 24 hours (Sat) + 24 hours (Sun) + 9 hours = 63 hours = 3780 minutes
		expected := (1440 - 1080) + 2*1440 + 540 // 360 + 2880 + 540 = 3780
		if got != expected {
			t.Errorf("expected %d minutes (Fri 18:00 → Mon 09:00), got %d", expected, got)
		}
	})
}

func TestAgent_WorkingHours_JSONExcluded(t *testing.T) {
	agent := Agent{
		PayloadUUID:       "test-uuid",
		WorkingHoursStart: 540,
		WorkingHoursEnd:   1020,
		WorkingDays:       []int{1, 2, 3},
	}

	data, err := json.Marshal(agent)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	jsonStr := string(data)
	if contains(jsonStr, "WorkingHours") || contains(jsonStr, "working_hours") {
		t.Error("working hours fields should be excluded from JSON (tagged json:\"-\")")
	}
	if contains(jsonStr, "WorkingDays") || contains(jsonStr, "working_days") {
		t.Error("working days field should be excluded from JSON (tagged json:\"-\")")
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
