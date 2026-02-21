package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

// --- ls command tests ---

func TestLsCommand_Execute(t *testing.T) {
	cmd := &LsCommand{}

	t.Run("current directory", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success for current dir, got %q: %s", result.Status, result.Output)
		}
	})

	t.Run("JSON params", func(t *testing.T) {
		tmp := t.TempDir()
		os.WriteFile(filepath.Join(tmp, "test.txt"), []byte("hi"), 0644)

		params, _ := json.Marshal(map[string]interface{}{"path": tmp})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "test.txt") {
			t.Errorf("output should contain test.txt, got: %s", result.Output)
		}
	})

	t.Run("JSON params with file_browser", func(t *testing.T) {
		tmp := t.TempDir()
		os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("data"), 0644)

		params, _ := json.Marshal(map[string]interface{}{"path": tmp, "file_browser": true})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		// Should return valid JSON
		var listing structs.FileListing
		if err := json.Unmarshal([]byte(result.Output), &listing); err != nil {
			t.Errorf("file_browser output should be JSON: %v", err)
		}
		if !listing.Success {
			t.Error("listing should report success")
		}
	})

	t.Run("nonexistent path", func(t *testing.T) {
		task := structs.Task{Params: "/nonexistent/path/xyz"}
		result := cmd.Execute(task)
		// ls on nonexistent path still returns "success" status but with Success=false in output
		if result.Status != "success" {
			t.Errorf("expected success status, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "Failed to list") {
			t.Errorf("output should indicate failure, got: %s", result.Output)
		}
	})

	t.Run("plain string path", func(t *testing.T) {
		tmp := t.TempDir()
		task := structs.Task{Params: tmp}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
	})

	t.Run("quoted path", func(t *testing.T) {
		tmp := t.TempDir()
		task := structs.Task{Params: `"` + tmp + `"`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success with quoted path, got %q: %s", result.Status, result.Output)
		}
	})
}

func TestPerformLs_File(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.txt")
	os.WriteFile(path, []byte("content"), 0644)

	result := performLs(path)
	if !result.Success {
		t.Error("expected success for file")
	}
	if !result.IsFile {
		t.Error("expected IsFile=true for file path")
	}
	if len(result.Files) != 1 {
		t.Fatalf("expected 1 file entry, got %d", len(result.Files))
	}
	if result.Files[0].Name != "test.txt" {
		t.Errorf("file name = %q, want %q", result.Files[0].Name, "test.txt")
	}
	if result.Files[0].Size != 7 {
		t.Errorf("file size = %d, want 7", result.Files[0].Size)
	}
	if !result.Files[0].IsFile {
		t.Error("file entry should have IsFile=true")
	}
}

func TestPerformLs_Directory(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("aaa"), 0644)
	os.WriteFile(filepath.Join(tmp, "b.txt"), []byte("bb"), 0644)
	os.Mkdir(filepath.Join(tmp, "subdir"), 0755)

	result := performLs(tmp)
	if !result.Success {
		t.Error("expected success for directory")
	}
	if result.IsFile {
		t.Error("expected IsFile=false for directory")
	}
	if len(result.Files) != 3 {
		t.Errorf("expected 3 entries, got %d", len(result.Files))
	}

	// Verify we have both files and a directory
	fileCount := 0
	dirCount := 0
	for _, f := range result.Files {
		if f.IsFile {
			fileCount++
		} else {
			dirCount++
		}
	}
	if fileCount != 2 || dirCount != 1 {
		t.Errorf("expected 2 files + 1 dir, got %d files + %d dirs", fileCount, dirCount)
	}
}

func TestPerformLs_NonexistentPath(t *testing.T) {
	result := performLs("/nonexistent/path/xyz")
	if result.Success {
		t.Error("expected Success=false for nonexistent path")
	}
}

func TestPerformLs_EmptyDir(t *testing.T) {
	tmp := t.TempDir()
	result := performLs(tmp)
	if !result.Success {
		t.Error("expected success for empty directory")
	}
	if len(result.Files) != 0 {
		t.Errorf("expected 0 entries in empty dir, got %d", len(result.Files))
	}
}

func TestFormatLsOutput_Failed(t *testing.T) {
	result := structs.FileListing{
		Success:    false,
		ParentPath: "/some/path",
	}
	output := formatLsOutput(result)
	if !strings.Contains(output, "Failed to list") {
		t.Errorf("output should indicate failure: %s", output)
	}
}

func TestFormatLsOutput_WithFiles(t *testing.T) {
	result := structs.FileListing{
		Success:    true,
		ParentPath: "/tmp",
		Files: []structs.FileListEntry{
			{Name: "test.txt", IsFile: true, Size: 100},
			{Name: "subdir", IsFile: false, Size: 4096},
		},
	}
	output := formatLsOutput(result)
	if !strings.Contains(output, "test.txt") {
		t.Error("output should contain test.txt")
	}
	if !strings.Contains(output, "FILE") {
		t.Error("output should contain FILE")
	}
	if !strings.Contains(output, "DIR") {
		t.Error("output should contain DIR")
	}
}

// --- ps command tests ---

func TestPsCommand_Execute(t *testing.T) {
	cmd := &PsCommand{}

	t.Run("no params", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "Total:") {
			t.Errorf("output should contain 'Total:', got: %s", result.Output[:min(100, len(result.Output))])
		}
	})

	t.Run("JSON params verbose", func(t *testing.T) {
		params, _ := json.Marshal(PsArgs{Verbose: true})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q", result.Status)
		}
		// Verbose mode should include "Command Line" header
		if !strings.Contains(result.Output, "Command Line") {
			t.Errorf("verbose output should contain 'Command Line' header")
		}
	})

	t.Run("JSON params with filter", func(t *testing.T) {
		// Filter for our own test process
		params, _ := json.Marshal(PsArgs{Filter: "go"})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
	})

	t.Run("CLI params -v", func(t *testing.T) {
		task := structs.Task{Params: "-v"}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "Command Line") {
			t.Errorf("verbose output should contain 'Command Line' header")
		}
	})

	t.Run("CLI params -i PID", func(t *testing.T) {
		// Filter for PID 1 (init/systemd)
		task := structs.Task{Params: "-i 1"}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
	})

	t.Run("CLI params filter string", func(t *testing.T) {
		task := structs.Task{Params: "nonexistent_process_name_xyz"}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "No processes found") {
			t.Errorf("should find no processes matching filter, got: %s", result.Output)
		}
	})

	t.Run("JSON params with PID", func(t *testing.T) {
		pid := int32(os.Getpid())
		params, _ := json.Marshal(PsArgs{PID: pid})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q", result.Status)
		}
	})
}

func TestFormatProcessList_Empty(t *testing.T) {
	output := formatProcessList(nil, false)
	if output != "No processes found" {
		t.Errorf("output = %q, want %q", output, "No processes found")
	}
}

func TestFormatProcessList_NonVerbose(t *testing.T) {
	procs := []ProcessInfo{
		{PID: 1, PPID: 0, Name: "init", Arch: "amd64", User: "root"},
		{PID: 100, PPID: 1, Name: "sshd", Arch: "amd64", User: ""},
	}
	output := formatProcessList(procs, false)
	if strings.Contains(output, "Command Line") {
		t.Error("non-verbose should not contain Command Line header")
	}
	if !strings.Contains(output, "init") {
		t.Error("output should contain init")
	}
	if !strings.Contains(output, "N/A") {
		t.Error("empty user should show N/A")
	}
	if !strings.Contains(output, "Total: 2") {
		t.Error("output should show total count")
	}
}

func TestFormatProcessList_Verbose(t *testing.T) {
	procs := []ProcessInfo{
		{PID: 1, PPID: 0, Name: "init", Arch: "amd64", User: "root", CmdLine: "/sbin/init"},
	}
	output := formatProcessList(procs, true)
	if !strings.Contains(output, "Command Line") {
		t.Error("verbose should contain Command Line header")
	}
	if !strings.Contains(output, "/sbin/init") {
		t.Error("verbose should show command line")
	}
}

// --- env command tests ---

func TestEnvCommand_Execute(t *testing.T) {
	cmd := &EnvCommand{}

	t.Run("no filter", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q", result.Status)
		}
		// Should contain at least PATH
		if !strings.Contains(result.Output, "PATH=") {
			t.Errorf("output should contain PATH=, got: %s", result.Output[:min(200, len(result.Output))])
		}
	})

	t.Run("filter match", func(t *testing.T) {
		// Set a unique env var for testing
		os.Setenv("FAWKES_TEST_VAR_XYZ", "test_value")
		defer os.Unsetenv("FAWKES_TEST_VAR_XYZ")

		task := structs.Task{Params: "FAWKES_TEST"}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "FAWKES_TEST_VAR_XYZ=test_value") {
			t.Errorf("output should contain our test var, got: %s", result.Output)
		}
	})

	t.Run("filter case insensitive", func(t *testing.T) {
		os.Setenv("FAWKES_CASE_TEST", "value")
		defer os.Unsetenv("FAWKES_CASE_TEST")

		task := structs.Task{Params: "fawkes_case"}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "FAWKES_CASE_TEST") {
			t.Errorf("case-insensitive filter should match, got: %s", result.Output)
		}
	})

	t.Run("filter no match", func(t *testing.T) {
		task := structs.Task{Params: "NONEXISTENT_VAR_XYZ_123"}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "No environment variables matching") {
			t.Errorf("should report no matches, got: %s", result.Output)
		}
	})

	t.Run("filter with whitespace", func(t *testing.T) {
		task := structs.Task{Params: "  PATH  "}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "PATH=") {
			t.Errorf("trimmed filter should match PATH, got: %s", result.Output)
		}
	})
}

// --- upload command tests ---

func TestUploadCommand_Execute(t *testing.T) {
	cmd := &UploadCommand{}

	t.Run("invalid JSON", func(t *testing.T) {
		task := structs.Task{Params: "not-json"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for invalid JSON, got %q", result.Status)
		}
	})

	t.Run("file exists without overwrite", func(t *testing.T) {
		tmp := t.TempDir()
		existingFile := filepath.Join(tmp, "existing.txt")
		os.WriteFile(existingFile, []byte("data"), 0644)

		params, _ := json.Marshal(UploadArgs{
			FileID:     "file-id-123",
			RemotePath: existingFile,
			Overwrite:  false,
		})

		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for existing file without overwrite, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "already exists") {
			t.Errorf("should mention file already exists, got: %s", result.Output)
		}
	})

	t.Run("tilde expansion", func(t *testing.T) {
		// Test that tilde expansion doesn't error (even though we can't test the full upload flow)
		params, _ := json.Marshal(UploadArgs{
			FileID:     "file-id-456",
			RemotePath: "~/test_upload_path",
			Overwrite:  true,
		})

		// This will fail at the file transfer stage (no Job), but we can verify
		// tilde expansion worked by checking the error message contains the expanded path
		task := structs.Task{Params: string(params)}
		// Can't execute full upload without Job channel, but parsing should succeed
		// We just verify the args parse correctly
		var args UploadArgs
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			t.Fatalf("failed to parse upload args: %v", err)
		}
		if args.RemotePath != "~/test_upload_path" {
			t.Errorf("remote_path = %q, want %q", args.RemotePath, "~/test_upload_path")
		}
	})

	t.Run("invalid write path", func(t *testing.T) {
		params, _ := json.Marshal(UploadArgs{
			FileID:     "file-id-789",
			RemotePath: "/nonexistent_dir/deeply/nested/file.txt",
			Overwrite:  true,
		})

		// Create a minimal Job with channels to avoid nil pointer
		job := &structs.Job{
			GetFileFromMythic: make(chan structs.GetFileFromMythicStruct, 1),
		}
		task := structs.Task{Params: string(params), Job: job}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for invalid write path, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "Failed to open") {
			t.Errorf("should mention failed to open, got: %s", result.Output)
		}
	})
}

// --- download command tests ---

func TestDownloadCommand_Execute(t *testing.T) {
	cmd := &DownloadCommand{}

	t.Run("empty params", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for empty params, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "No file path") {
			t.Errorf("should mention no file path, got: %s", result.Output)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		task := structs.Task{Params: "/nonexistent/file.txt"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent file, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "Error opening file") {
			t.Errorf("should mention error opening, got: %s", result.Output)
		}
	})

	t.Run("quoted path nonexistent", func(t *testing.T) {
		task := structs.Task{Params: `"/nonexistent/file.txt"`}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent quoted path, got %q", result.Status)
		}
	})

	t.Run("successful download with real file", func(t *testing.T) {
		tmp := t.TempDir()
		testFile := filepath.Join(tmp, "testfile.txt")
		os.WriteFile(testFile, []byte("download content"), 0644)

		sendCh := make(chan structs.SendFileToMythicStruct, 1)
		stop := 0
		job := &structs.Job{
			Stop:             &stop,
			SendResponses:    make(chan structs.Response, 100),
			SendFileToMythic: sendCh,
			FileTransfers:    make(map[string]chan json.RawMessage),
		}

		task := structs.NewTask("dl-task-1", "download", testFile)
		task.Job = job

		// Run download in background; it will block waiting for transfer to complete
		done := make(chan structs.CommandResult, 1)
		go func() {
			done <- cmd.Execute(task)
		}()

		// Consume the SendFileToMythic message and immediately signal finished
		select {
		case msg := <-sendCh:
			// Verify the message was set up correctly
			if msg.FullPath == "" {
				t.Error("Expected non-empty FullPath")
			}
			if msg.File == nil {
				t.Error("Expected non-nil File")
			}
			if msg.IsScreenshot {
				t.Error("Expected IsScreenshot=false")
			}
			if !msg.SendUserStatusUpdates {
				t.Error("Expected SendUserStatusUpdates=true")
			}
			// Signal transfer complete
			msg.FinishedTransfer <- 1
		case <-time.After(3 * time.Second):
			t.Fatal("Timed out waiting for SendFileToMythic message")
		}

		select {
		case result := <-done:
			if result.Status != "success" {
				t.Errorf("expected success, got %q: %s", result.Status, result.Output)
			}
			if !strings.Contains(result.Output, "Finished Downloading") {
				t.Errorf("expected 'Finished Downloading', got: %s", result.Output)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Timed out waiting for download result")
		}
	})

	t.Run("download stopped early", func(t *testing.T) {
		tmp := t.TempDir()
		testFile := filepath.Join(tmp, "stopfile.txt")
		os.WriteFile(testFile, []byte("stop content"), 0644)

		sendCh := make(chan structs.SendFileToMythicStruct, 1)
		stop := 0
		job := &structs.Job{
			Stop:             &stop,
			SendResponses:    make(chan structs.Response, 100),
			SendFileToMythic: sendCh,
			FileTransfers:    make(map[string]chan json.RawMessage),
		}

		task := structs.NewTask("dl-task-stop", "download", testFile)
		task.Job = job

		done := make(chan structs.CommandResult, 1)
		go func() {
			done <- cmd.Execute(task)
		}()

		// Consume the channel message but don't finish — set stop instead
		select {
		case <-sendCh:
			task.SetStop()
		case <-time.After(3 * time.Second):
			t.Fatal("Timed out waiting for SendFileToMythic")
		}

		select {
		case result := <-done:
			if result.Status != "error" {
				t.Errorf("expected error for stopped task, got %q", result.Status)
			}
			if !strings.Contains(result.Output, "Tasked to stop") {
				t.Errorf("expected 'Tasked to stop', got: %s", result.Output)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Timed out waiting for stopped download result")
		}
	})
}

// --- upload command full-flow tests ---

func TestUploadCommand_FullFlow(t *testing.T) {
	cmd := &UploadCommand{}

	t.Run("successful upload to new file", func(t *testing.T) {
		tmp := t.TempDir()
		uploadPath := filepath.Join(tmp, "uploaded.bin")

		getCh := make(chan structs.GetFileFromMythicStruct, 1)
		stop := 0
		job := &structs.Job{
			Stop:              &stop,
			SendResponses:     make(chan structs.Response, 100),
			GetFileFromMythic: getCh,
			FileTransfers:     make(map[string]chan json.RawMessage),
		}

		params, _ := json.Marshal(UploadArgs{
			FileID:     "test-file-id",
			RemotePath: uploadPath,
			Overwrite:  false,
		})

		task := structs.NewTask("ul-task-1", "upload", string(params))
		task.Job = job

		done := make(chan structs.CommandResult, 1)
		go func() {
			done <- cmd.Execute(task)
		}()

		// Consume the GetFileFromMythic message and provide chunks
		select {
		case msg := <-getCh:
			if msg.FileID != "test-file-id" {
				t.Errorf("expected file ID 'test-file-id', got %q", msg.FileID)
			}
			// Send some data chunks
			msg.ReceivedChunkChannel <- []byte("chunk1-data")
			msg.ReceivedChunkChannel <- []byte("-chunk2-data")
			// Signal done
			msg.ReceivedChunkChannel <- []byte{}
		case <-time.After(3 * time.Second):
			t.Fatal("Timed out waiting for GetFileFromMythic")
		}

		select {
		case result := <-done:
			if result.Status != "success" {
				t.Errorf("expected success, got %q: %s", result.Status, result.Output)
			}
			if !strings.Contains(result.Output, "Uploaded") {
				t.Errorf("expected 'Uploaded' in output, got: %s", result.Output)
			}
			if !strings.Contains(result.Output, "23 bytes") {
				t.Errorf("expected '23 bytes' in output, got: %s", result.Output)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Timed out waiting for upload result")
		}

		// Verify file content
		content, err := os.ReadFile(uploadPath)
		if err != nil {
			t.Fatalf("Failed to read uploaded file: %v", err)
		}
		if string(content) != "chunk1-data-chunk2-data" {
			t.Errorf("File content mismatch: got %q", string(content))
		}
	})

	t.Run("upload with overwrite", func(t *testing.T) {
		tmp := t.TempDir()
		uploadPath := filepath.Join(tmp, "overwrite.bin")
		os.WriteFile(uploadPath, []byte("old content"), 0644)

		getCh := make(chan structs.GetFileFromMythicStruct, 1)
		stop := 0
		job := &structs.Job{
			Stop:              &stop,
			SendResponses:     make(chan structs.Response, 100),
			GetFileFromMythic: getCh,
			FileTransfers:     make(map[string]chan json.RawMessage),
		}

		params, _ := json.Marshal(UploadArgs{
			FileID:     "overwrite-file",
			RemotePath: uploadPath,
			Overwrite:  true,
		})

		task := structs.NewTask("ul-task-ow", "upload", string(params))
		task.Job = job

		done := make(chan structs.CommandResult, 1)
		go func() {
			done <- cmd.Execute(task)
		}()

		select {
		case msg := <-getCh:
			msg.ReceivedChunkChannel <- []byte("new content")
			msg.ReceivedChunkChannel <- []byte{}
		case <-time.After(3 * time.Second):
			t.Fatal("Timed out")
		}

		select {
		case result := <-done:
			if result.Status != "success" {
				t.Errorf("expected success, got %q: %s", result.Status, result.Output)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Timed out")
		}

		content, _ := os.ReadFile(uploadPath)
		if string(content) != "new content" {
			t.Errorf("File not overwritten: got %q", string(content))
		}
	})

	t.Run("upload with tilde path", func(t *testing.T) {
		// Test tilde expansion through the full flow
		getCh := make(chan structs.GetFileFromMythicStruct, 1)
		stop := 0
		job := &structs.Job{
			Stop:              &stop,
			SendResponses:     make(chan structs.Response, 100),
			GetFileFromMythic: getCh,
			FileTransfers:     make(map[string]chan json.RawMessage),
		}

		homeDir, _ := os.UserHomeDir()
		uploadPath := filepath.Join(homeDir, "test_upload_tilde_coverage.tmp")
		defer os.Remove(uploadPath)

		params, _ := json.Marshal(UploadArgs{
			FileID:     "tilde-file",
			RemotePath: "~/test_upload_tilde_coverage.tmp",
			Overwrite:  true,
		})

		task := structs.NewTask("ul-task-tilde", "upload", string(params))
		task.Job = job

		done := make(chan structs.CommandResult, 1)
		go func() {
			done <- cmd.Execute(task)
		}()

		select {
		case msg := <-getCh:
			// Verify the path was expanded
			if !strings.HasPrefix(msg.FullPath, homeDir) {
				t.Errorf("expected path starting with %s, got %s", homeDir, msg.FullPath)
			}
			msg.ReceivedChunkChannel <- []byte("tilde data")
			msg.ReceivedChunkChannel <- []byte{}
		case <-time.After(3 * time.Second):
			t.Fatal("Timed out")
		}

		select {
		case result := <-done:
			if result.Status != "success" {
				t.Errorf("expected success, got %q: %s", result.Status, result.Output)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Timed out")
		}
	})

	t.Run("upload empty transfer (zero bytes)", func(t *testing.T) {
		tmp := t.TempDir()
		uploadPath := filepath.Join(tmp, "empty.bin")

		getCh := make(chan structs.GetFileFromMythicStruct, 1)
		stop := 0
		job := &structs.Job{
			Stop:              &stop,
			SendResponses:     make(chan structs.Response, 100),
			GetFileFromMythic: getCh,
			FileTransfers:     make(map[string]chan json.RawMessage),
		}

		params, _ := json.Marshal(UploadArgs{
			FileID:     "empty-file",
			RemotePath: uploadPath,
			Overwrite:  false,
		})

		task := structs.NewTask("ul-task-empty", "upload", string(params))
		task.Job = job

		done := make(chan structs.CommandResult, 1)
		go func() {
			done <- cmd.Execute(task)
		}()

		select {
		case msg := <-getCh:
			// Immediately signal done (no data)
			msg.ReceivedChunkChannel <- []byte{}
		case <-time.After(3 * time.Second):
			t.Fatal("Timed out")
		}

		select {
		case result := <-done:
			if result.Status != "success" {
				t.Errorf("expected success for empty upload, got %q: %s", result.Status, result.Output)
			}
			if !strings.Contains(result.Output, "0 bytes") {
				t.Errorf("expected '0 bytes' in output, got: %s", result.Output)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Timed out")
		}
	})
}

// --- cp command additional tests ---

func TestCpCommand_Execute_Detailed(t *testing.T) {
	cmd := &CpCommand{}

	t.Run("JSON params copy file", func(t *testing.T) {
		tmp := t.TempDir()
		src := filepath.Join(tmp, "src.txt")
		dst := filepath.Join(tmp, "dst.txt")
		os.WriteFile(src, []byte("copied content"), 0644)

		params, _ := json.Marshal(map[string]string{"source": src, "destination": dst})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}

		// Verify the file was copied
		data, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("failed to read copied file: %v", err)
		}
		if string(data) != "copied content" {
			t.Errorf("copied content = %q, want %q", string(data), "copied content")
		}
	})

	t.Run("source does not exist", func(t *testing.T) {
		tmp := t.TempDir()
		params, _ := json.Marshal(map[string]string{"source": "/nonexistent", "destination": filepath.Join(tmp, "dst.txt")})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent source, got %q", result.Status)
		}
	})
}

// --- mv command additional tests ---

func TestMvCommand_Execute_Detailed(t *testing.T) {
	cmd := &MvCommand{}

	t.Run("JSON params move file", func(t *testing.T) {
		tmp := t.TempDir()
		src := filepath.Join(tmp, "original.txt")
		dst := filepath.Join(tmp, "moved.txt")
		os.WriteFile(src, []byte("move me"), 0644)

		params, _ := json.Marshal(map[string]string{"source": src, "destination": dst})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}

		// Verify source is gone and dest exists
		if _, err := os.Stat(src); !os.IsNotExist(err) {
			t.Error("source file should no longer exist")
		}
		data, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("failed to read moved file: %v", err)
		}
		if string(data) != "move me" {
			t.Errorf("moved content = %q, want %q", string(data), "move me")
		}
	})

	t.Run("source does not exist", func(t *testing.T) {
		tmp := t.TempDir()
		params, _ := json.Marshal(map[string]string{"source": "/nonexistent", "destination": filepath.Join(tmp, "dst.txt")})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent source, got %q", result.Status)
		}
	})

	t.Run("empty params", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for empty params, got %q", result.Status)
		}
	})
}

// --- ls getHostname test ---

func TestLsGetHostname(t *testing.T) {
	hostname := getHostname()
	if hostname == "" {
		t.Error("getHostname should not return empty string")
	}
}
