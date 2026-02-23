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

// =============================================================================
// socks command tests
// =============================================================================

func TestSocksCommand(t *testing.T) {
	cmd := &SocksCommand{}

	if cmd.Name() != "socks" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "socks")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}

	t.Run("start action", func(t *testing.T) {
		params, _ := json.Marshal(map[string]interface{}{"action": "start", "port": 1080})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "completed" {
			t.Errorf("expected completed, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "1080") {
			t.Errorf("output should contain port, got: %s", result.Output)
		}
		if !strings.Contains(result.Output, "SOCKS5") {
			t.Errorf("output should mention SOCKS5, got: %s", result.Output)
		}
	})

	t.Run("stop action", func(t *testing.T) {
		params, _ := json.Marshal(map[string]interface{}{"action": "stop", "port": 1080})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "completed" {
			t.Errorf("expected completed, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "stopped") {
			t.Errorf("output should mention stopped, got: %s", result.Output)
		}
	})

	t.Run("unknown action", func(t *testing.T) {
		params, _ := json.Marshal(map[string]interface{}{"action": "restart", "port": 1080})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for unknown action, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "restart") {
			t.Errorf("error should mention the bad action, got: %s", result.Output)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		task := structs.Task{Params: "not json"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for invalid JSON, got %q", result.Status)
		}
	})

	t.Run("empty action", func(t *testing.T) {
		params, _ := json.Marshal(map[string]interface{}{"action": "", "port": 1080})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for empty action, got %q", result.Status)
		}
	})
}

// =============================================================================
// arp command tests
// =============================================================================

func TestArpCommand_NativeAPI(t *testing.T) {
	cmd := &ArpCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	// Should succeed (even if no ARP entries on test host)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
	// Output should use the new formatted table
	if !strings.Contains(result.Output, "ARP entries") && !strings.Contains(result.Output, "No ARP entries") {
		t.Errorf("expected ARP output, got: %s", result.Output)
	}
}

func TestGetArpTable_Native(t *testing.T) {
	entries, err := getArpTable()
	if err != nil {
		t.Fatalf("getArpTable() error: %v", err)
	}
	// On any machine with a network, there should be at least the gateway
	if len(entries) > 0 {
		for _, e := range entries {
			if e.IP == "" {
				t.Error("ARP entry has empty IP")
			}
			if e.MAC == "" {
				t.Error("ARP entry has empty MAC")
			}
		}
		t.Logf("Found %d ARP entries", len(entries))
	}
}

func TestArpCommand_Name(t *testing.T) {
	cmd := &ArpCommand{}
	if cmd.Name() != "arp" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "arp")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

// =============================================================================
// netstat helper function tests
// =============================================================================

func TestFormatAddr(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		port     uint32
		expected string
	}{
		{"normal", "192.168.1.1", 80, "192.168.1.1:80"},
		{"high port", "10.0.0.1", 65535, "10.0.0.1:65535"},
		{"empty IP", "", 80, "*:80"},
		{"zero port", "192.168.1.1", 0, "192.168.1.1:*"},
		{"both empty", "", 0, "*:*"},
		{"ipv6", "::1", 443, "::1:443"},
		{"localhost", "127.0.0.1", 8080, "127.0.0.1:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatAddr(tt.ip, tt.port)
			if result != tt.expected {
				t.Errorf("formatAddr(%q, %d) = %q, want %q", tt.ip, tt.port, result, tt.expected)
			}
		})
	}
}

func TestProtoName(t *testing.T) {
	tests := []struct {
		connType uint32
		expected string
	}{
		{1, "TCP"},
		{2, "UDP"},
		{0, "0"},
		{3, "3"},
		{99, "99"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := protoName(tt.connType)
			if result != tt.expected {
				t.Errorf("protoName(%d) = %q, want %q", tt.connType, result, tt.expected)
			}
		})
	}
}

func TestStatusPriority(t *testing.T) {
	tests := []struct {
		status   string
		expected int
	}{
		{"LISTEN", 0},
		{"ESTABLISHED", 1},
		{"TIME_WAIT", 3},
		{"CLOSE_WAIT", 4},
		{"SYN_SENT", 2},
		{"UNKNOWN", 2},
		{"", 2},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			result := statusPriority(tt.status)
			if result != tt.expected {
				t.Errorf("statusPriority(%q) = %d, want %d", tt.status, result, tt.expected)
			}
		})
	}

	// Verify ordering: LISTEN < ESTABLISHED < default < TIME_WAIT < CLOSE_WAIT
	if statusPriority("LISTEN") >= statusPriority("ESTABLISHED") {
		t.Error("LISTEN should sort before ESTABLISHED")
	}
	if statusPriority("ESTABLISHED") >= statusPriority("TIME_WAIT") {
		t.Error("ESTABLISHED should sort before TIME_WAIT")
	}
}

func TestNetstatCommand_Name(t *testing.T) {
	cmd := &NetstatCommand{}
	if cmd.Name() != "net-stat" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "net-stat")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

// =============================================================================
// timestomp command tests
// =============================================================================

func TestTimestompCommand(t *testing.T) {
	cmd := &TimestompCommand{}

	if cmd.Name() != "timestomp" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "timestomp")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}

	t.Run("invalid JSON params", func(t *testing.T) {
		task := structs.Task{Params: "not json"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error, got %q", result.Status)
		}
	})

	t.Run("missing target", func(t *testing.T) {
		params, _ := json.Marshal(TimestompParams{Action: "get", Target: ""})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for missing target, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "target") {
			t.Errorf("error should mention target, got: %s", result.Output)
		}
	})

	t.Run("unknown action", func(t *testing.T) {
		params, _ := json.Marshal(TimestompParams{Action: "delete", Target: "/tmp/file"})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for unknown action, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "delete") {
			t.Errorf("error should mention the bad action, got: %s", result.Output)
		}
	})

	t.Run("get timestamps", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "test.txt")
		if err := os.WriteFile(path, []byte("content"), 0644); err != nil {
			t.Fatal(err)
		}

		params, _ := json.Marshal(TimestompParams{Action: "get", Target: path})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "Modified:") {
			t.Errorf("output should contain Modified timestamp, got: %s", result.Output)
		}
	})

	t.Run("get nonexistent file", func(t *testing.T) {
		params, _ := json.Marshal(TimestompParams{Action: "get", Target: "/nonexistent/file"})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent file, got %q", result.Status)
		}
	})

	t.Run("set timestamp RFC3339", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "test.txt")
		if err := os.WriteFile(path, []byte("content"), 0644); err != nil {
			t.Fatal(err)
		}

		targetTime := "2020-01-15T10:30:00Z"
		params, _ := json.Marshal(TimestompParams{Action: "set", Target: path, Timestamp: targetTime})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}

		// Verify the modification time was actually changed
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		expected, _ := time.Parse(time.RFC3339, targetTime)
		if !info.ModTime().Equal(expected) {
			t.Errorf("ModTime = %v, want %v", info.ModTime(), expected)
		}
	})

	t.Run("set timestamp date only", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "test.txt")
		if err := os.WriteFile(path, []byte("content"), 0644); err != nil {
			t.Fatal(err)
		}

		params, _ := json.Marshal(TimestompParams{Action: "set", Target: path, Timestamp: "2019-06-15"})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
	})

	t.Run("set timestamp datetime format", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "test.txt")
		if err := os.WriteFile(path, []byte("content"), 0644); err != nil {
			t.Fatal(err)
		}

		params, _ := json.Marshal(TimestompParams{Action: "set", Target: path, Timestamp: "2018-03-20 14:30:00"})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
	})

	t.Run("set invalid timestamp format", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "test.txt")
		if err := os.WriteFile(path, []byte("content"), 0644); err != nil {
			t.Fatal(err)
		}

		params, _ := json.Marshal(TimestompParams{Action: "set", Target: path, Timestamp: "not-a-date"})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for invalid timestamp, got %q", result.Status)
		}
	})

	t.Run("set empty timestamp", func(t *testing.T) {
		params, _ := json.Marshal(TimestompParams{Action: "set", Target: "/tmp/file", Timestamp: ""})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for empty timestamp, got %q", result.Status)
		}
	})

	t.Run("copy timestamps", func(t *testing.T) {
		tmp := t.TempDir()
		src := filepath.Join(tmp, "source.txt")
		dst := filepath.Join(tmp, "dest.txt")
		if err := os.WriteFile(src, []byte("source"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte("dest"), 0644); err != nil {
			t.Fatal(err)
		}

		// Set source to a known old time
		oldTime := time.Date(2015, 6, 15, 10, 0, 0, 0, time.UTC)
		os.Chtimes(src, oldTime, oldTime)

		params, _ := json.Marshal(TimestompParams{Action: "copy", Target: dst, Source: src})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}

		// Verify dest has source's timestamps
		dstInfo, _ := os.Stat(dst)
		if !dstInfo.ModTime().Equal(oldTime) {
			t.Errorf("dest ModTime = %v, want %v", dstInfo.ModTime(), oldTime)
		}
	})

	t.Run("copy missing source", func(t *testing.T) {
		params, _ := json.Marshal(TimestompParams{Action: "copy", Target: "/tmp/file", Source: ""})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for missing source, got %q", result.Status)
		}
	})

	t.Run("copy nonexistent source", func(t *testing.T) {
		params, _ := json.Marshal(TimestompParams{Action: "copy", Target: "/tmp/file", Source: "/nonexistent"})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent source, got %q", result.Status)
		}
	})

	t.Run("set nonexistent target", func(t *testing.T) {
		params, _ := json.Marshal(TimestompParams{Action: "set", Target: "/nonexistent/target", Timestamp: "2020-01-01"})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent target, got %q", result.Status)
		}
	})
}

// =============================================================================
// upload command tests (parameter parsing only, no file transfer)
// =============================================================================

func TestUploadCommand(t *testing.T) {
	cmd := &UploadCommand{}

	if cmd.Name() != "upload" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "upload")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}

	t.Run("invalid JSON", func(t *testing.T) {
		task := structs.Task{Params: "not json"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for invalid JSON, got %q", result.Status)
		}
	})

	t.Run("file already exists without overwrite", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "existing.txt")
		os.WriteFile(path, []byte("existing"), 0644)

		params, _ := json.Marshal(UploadArgs{FileID: "test-id", RemotePath: path, Overwrite: false})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error when file exists and overwrite=false, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "already exists") {
			t.Errorf("error should mention file exists, got: %s", result.Output)
		}
	})

	t.Run("tilde expansion", func(t *testing.T) {
		// We can't fully test tilde expansion since it requires channel setup,
		// but we can verify the path resolves
		params, _ := json.Marshal(UploadArgs{FileID: "test-id", RemotePath: "~/nonexistent_test_dir/file.txt"})
		task := structs.Task{Params: string(params)}
		// This will fail at OpenFile (directory doesn't exist), but path should be resolved
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error (dir doesn't exist), got %q", result.Status)
		}
		// Should NOT contain tilde — path was resolved
		if strings.Contains(result.Output, "~/") {
			t.Errorf("tilde should be expanded, got: %s", result.Output)
		}
	})

	t.Run("invalid path", func(t *testing.T) {
		params, _ := json.Marshal(UploadArgs{FileID: "test-id", RemotePath: "/nonexistent_dir/sub/file.txt"})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for invalid path, got %q", result.Status)
		}
	})
}

