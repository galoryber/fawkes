package commands

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

// =============================================================================
// find command tests
// =============================================================================

func TestFindCommand(t *testing.T) {
	cmd := &FindCommand{}

	if cmd.Name() != "find" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "find")
	}

	t.Run("empty params", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for empty params, got %q", result.Status)
		}
	})

	t.Run("plain text as pattern", func(t *testing.T) {
		task := structs.Task{Params: "*.go"}
		result := cmd.Execute(task)
		// Plain text treated as pattern — should not return a parse error
		if result.Status == "error" && strings.Contains(result.Output, "Error parsing") {
			t.Errorf("plain text should be treated as pattern, got parse error: %s", result.Output)
		}
	})

	t.Run("missing pattern", func(t *testing.T) {
		task := structs.Task{Params: `{"path":"."}`}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for missing pattern, got %q", result.Status)
		}
	})

	t.Run("find files by pattern", func(t *testing.T) {
		tmp := t.TempDir()
		os.WriteFile(filepath.Join(tmp, "test.txt"), []byte("a"), 0644)
		os.WriteFile(filepath.Join(tmp, "test.log"), []byte("b"), 0644)
		os.WriteFile(filepath.Join(tmp, "other.txt"), []byte("c"), 0644)

		params, _ := json.Marshal(FindParams{Path: tmp, Pattern: "*.txt"})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "2 match") {
			t.Errorf("expected 2 matches, got: %s", result.Output)
		}
		if !strings.Contains(result.Output, "test.txt") {
			t.Errorf("expected test.txt in output: %s", result.Output)
		}
		if !strings.Contains(result.Output, "other.txt") {
			t.Errorf("expected other.txt in output: %s", result.Output)
		}
	})

	t.Run("find with depth limit", func(t *testing.T) {
		tmp := t.TempDir()
		os.WriteFile(filepath.Join(tmp, "top.txt"), []byte("a"), 0644)
		os.MkdirAll(filepath.Join(tmp, "sub1"), 0755)
		os.WriteFile(filepath.Join(tmp, "sub1", "mid.txt"), []byte("b"), 0644)
		os.MkdirAll(filepath.Join(tmp, "sub1", "sub2"), 0755)
		os.WriteFile(filepath.Join(tmp, "sub1", "sub2", "deep.txt"), []byte("c"), 0644)

		// max_depth=1: only finds files directly in the search path (depth 1)
		params, _ := json.Marshal(FindParams{Path: tmp, Pattern: "*.txt", MaxDepth: 1})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "top.txt") {
			t.Errorf("expected top.txt in output: %s", result.Output)
		}
		if strings.Contains(result.Output, "deep.txt") {
			t.Errorf("deep.txt should be excluded at depth 1: %s", result.Output)
		}

		// max_depth=3: should find all files
		params3, _ := json.Marshal(FindParams{Path: tmp, Pattern: "*.txt", MaxDepth: 3})
		task3 := structs.Task{Params: string(params3)}
		result3 := cmd.Execute(task3)
		if result3.Status != "success" {
			t.Errorf("expected success, got %q: %s", result3.Status, result3.Output)
		}
		if !strings.Contains(result3.Output, "3 match") {
			t.Errorf("expected 3 matches with depth=3, got: %s", result3.Output)
		}
	})

	t.Run("no matches", func(t *testing.T) {
		tmp := t.TempDir()
		os.WriteFile(filepath.Join(tmp, "test.txt"), []byte("a"), 0644)

		params, _ := json.Marshal(FindParams{Path: tmp, Pattern: "*.xyz"})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success (no matches), got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "No files matching") {
			t.Errorf("expected 'No files matching' message: %s", result.Output)
		}
	})

	t.Run("find directories", func(t *testing.T) {
		tmp := t.TempDir()
		os.MkdirAll(filepath.Join(tmp, "testdir"), 0755)
		os.WriteFile(filepath.Join(tmp, "testfile"), []byte("a"), 0644)

		params, _ := json.Marshal(FindParams{Path: tmp, Pattern: "test*"})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "<DIR>") {
			t.Errorf("expected <DIR> for directory entry: %s", result.Output)
		}
	})
}

// =============================================================================
// sleep command tests (AgentCommand interface)
// =============================================================================

func TestSleepCommand(t *testing.T) {
	cmd := &SleepCommand{}

	if cmd.Name() != "sleep" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "sleep")
	}

	t.Run("execute without agent returns error", func(t *testing.T) {
		task := structs.Task{Params: "10"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("Execute() should return error without agent, got %q", result.Status)
		}
	})

	t.Run("JSON params", func(t *testing.T) {
		agent := &structs.Agent{SleepInterval: 10, Jitter: 10}
		task := structs.Task{Params: `{"interval":5,"jitter":20}`}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if agent.SleepInterval != 5 {
			t.Errorf("expected interval=5, got %d", agent.SleepInterval)
		}
		if agent.Jitter != 20 {
			t.Errorf("expected jitter=20, got %d", agent.Jitter)
		}
	})

	t.Run("space-separated params", func(t *testing.T) {
		agent := &structs.Agent{SleepInterval: 10, Jitter: 10}
		task := structs.Task{Params: "30 50"}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if agent.SleepInterval != 30 {
			t.Errorf("expected interval=30, got %d", agent.SleepInterval)
		}
		if agent.Jitter != 50 {
			t.Errorf("expected jitter=50, got %d", agent.Jitter)
		}
	})

	t.Run("interval only", func(t *testing.T) {
		agent := &structs.Agent{SleepInterval: 10, Jitter: 10}
		task := structs.Task{Params: "15"}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if agent.SleepInterval != 15 {
			t.Errorf("expected interval=15, got %d", agent.SleepInterval)
		}
	})

	t.Run("negative interval", func(t *testing.T) {
		agent := &structs.Agent{SleepInterval: 10, Jitter: 10}
		task := structs.Task{Params: `{"interval":-1,"jitter":10}`}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "error" {
			t.Errorf("expected error for negative interval, got %q", result.Status)
		}
	})

	t.Run("jitter out of range", func(t *testing.T) {
		agent := &structs.Agent{SleepInterval: 10, Jitter: 10}
		task := structs.Task{Params: `{"interval":10,"jitter":101}`}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "error" {
			t.Errorf("expected error for jitter>100, got %q", result.Status)
		}
	})

	t.Run("invalid interval string", func(t *testing.T) {
		agent := &structs.Agent{SleepInterval: 10, Jitter: 10}
		task := structs.Task{Params: "abc"}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "error" {
			t.Errorf("expected error for non-numeric interval, got %q", result.Status)
		}
	})

	t.Run("zero interval allowed", func(t *testing.T) {
		agent := &structs.Agent{SleepInterval: 10, Jitter: 10}
		task := structs.Task{Params: `{"interval":0,"jitter":0}`}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "success" {
			t.Errorf("expected success for zero interval, got %q: %s", result.Status, result.Output)
		}
		if agent.SleepInterval != 0 {
			t.Errorf("expected interval=0, got %d", agent.SleepInterval)
		}
	})

	t.Run("working hours via JSON", func(t *testing.T) {
		agent := &structs.Agent{SleepInterval: 10, Jitter: 10}
		task := structs.Task{Params: `{"interval":10,"jitter":10,"working_start":"09:00","working_end":"17:00","working_days":"1,2,3,4,5"}`}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if agent.WorkingHoursStart != 540 {
			t.Errorf("expected WorkingHoursStart=540, got %d", agent.WorkingHoursStart)
		}
		if agent.WorkingHoursEnd != 1020 {
			t.Errorf("expected WorkingHoursEnd=1020, got %d", agent.WorkingHoursEnd)
		}
		if len(agent.WorkingDays) != 5 {
			t.Errorf("expected 5 working days, got %d", len(agent.WorkingDays))
		}
	})

	t.Run("working hours via space-separated", func(t *testing.T) {
		agent := &structs.Agent{SleepInterval: 10, Jitter: 10}
		task := structs.Task{Params: "10 10 09:00 17:00 1,2,3,4,5"}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if agent.WorkingHoursStart != 540 {
			t.Errorf("expected WorkingHoursStart=540, got %d", agent.WorkingHoursStart)
		}
		if agent.WorkingHoursEnd != 1020 {
			t.Errorf("expected WorkingHoursEnd=1020, got %d", agent.WorkingHoursEnd)
		}
	})

	t.Run("disable working hours", func(t *testing.T) {
		agent := &structs.Agent{
			SleepInterval:     10,
			Jitter:            10,
			WorkingHoursStart: 540,
			WorkingHoursEnd:   1020,
			WorkingDays:       []int{1, 2, 3, 4, 5},
		}
		task := structs.Task{Params: `{"interval":10,"jitter":10,"working_start":"00:00","working_end":"00:00"}`}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if agent.WorkingHoursStart != 0 || agent.WorkingHoursEnd != 0 {
			t.Error("working hours should be disabled (0,0)")
		}
	})

	t.Run("invalid working_start format", func(t *testing.T) {
		agent := &structs.Agent{SleepInterval: 10, Jitter: 10}
		task := structs.Task{Params: `{"interval":10,"jitter":10,"working_start":"bad","working_end":"17:00"}`}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "error" {
			t.Errorf("expected error for invalid working_start, got %q", result.Status)
		}
	})

	t.Run("invalid working_days format", func(t *testing.T) {
		agent := &structs.Agent{SleepInterval: 10, Jitter: 10}
		task := structs.Task{Params: `{"interval":10,"jitter":10,"working_start":"09:00","working_end":"17:00","working_days":"abc"}`}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "error" {
			t.Errorf("expected error for invalid working_days, got %q", result.Status)
		}
	})

	t.Run("update days only", func(t *testing.T) {
		agent := &structs.Agent{
			SleepInterval:     10,
			Jitter:            10,
			WorkingHoursStart: 540,
			WorkingHoursEnd:   1020,
		}
		task := structs.Task{Params: `{"interval":10,"jitter":10,"working_days":"1,3,5"}`}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if len(agent.WorkingDays) != 3 {
			t.Errorf("expected 3 working days, got %d", len(agent.WorkingDays))
		}
		// Start/end should be unchanged
		if agent.WorkingHoursStart != 540 {
			t.Errorf("WorkingHoursStart should be unchanged, got %d", agent.WorkingHoursStart)
		}
	})

	t.Run("disable days only", func(t *testing.T) {
		agent := &structs.Agent{
			SleepInterval: 10,
			Jitter:        10,
			WorkingDays:   []int{1, 2, 3},
		}
		task := structs.Task{Params: `{"interval":10,"jitter":10,"working_days":"0"}`}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if agent.WorkingDays != nil {
			t.Errorf("expected nil working days, got %v", agent.WorkingDays)
		}
	})

	t.Run("no working hours change when not specified", func(t *testing.T) {
		agent := &structs.Agent{
			SleepInterval:     10,
			Jitter:            10,
			WorkingHoursStart: 540,
			WorkingHoursEnd:   1020,
			WorkingDays:       []int{1, 2, 3, 4, 5},
		}
		task := structs.Task{Params: `{"interval":20,"jitter":30}`}
		result := cmd.ExecuteWithAgent(task, agent)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if agent.WorkingHoursStart != 540 || agent.WorkingHoursEnd != 1020 {
			t.Error("working hours should be unchanged when not specified")
		}
		if len(agent.WorkingDays) != 5 {
			t.Error("working days should be unchanged when not specified")
		}
	})
}

// =============================================================================
// whoami command tests (Linux-only)
// =============================================================================

func TestWhoamiCommand(t *testing.T) {
	cmd := &WhoamiCommand{}

	if cmd.Name() != "whoami" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "whoami")
	}

	t.Run("basic execution", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "User:") {
			t.Errorf("expected 'User:' in output: %s", result.Output)
		}
		if !strings.Contains(result.Output, "UID:") {
			t.Errorf("expected 'UID:' in output: %s", result.Output)
		}
		if !strings.Contains(result.Output, "GID:") {
			t.Errorf("expected 'GID:' in output: %s", result.Output)
		}
	})

	t.Run("groups section", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "Groups:") {
			t.Errorf("expected 'Groups:' section in output: %s", result.Output)
		}
		// Should have at least one group (primary group)
		if !strings.Contains(result.Output, "gid=") {
			t.Errorf("expected group entries with gid= in output: %s", result.Output)
		}
	})
}

// =============================================================================
// ifconfig command tests
// =============================================================================

func TestIfconfigCommand(t *testing.T) {
	cmd := &IfconfigCommand{}

	if cmd.Name() != "ifconfig" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "ifconfig")
	}

	t.Run("basic execution", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		// Should contain at least the loopback interface
		if !strings.Contains(result.Output, "lo") {
			t.Errorf("expected loopback 'lo' in output: %s", result.Output)
		}
	})
}

// =============================================================================
// run command tests
// =============================================================================

func TestRunCommand(t *testing.T) {
	cmd := &RunCommand{}

	if cmd.Name() != "run" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "run")
	}

	t.Run("empty params", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for empty params, got %q", result.Status)
		}
	})

	t.Run("echo command", func(t *testing.T) {
		task := structs.Task{Params: "echo hello world"}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "hello world") {
			t.Errorf("expected 'hello world' in output: %s", result.Output)
		}
	})

	t.Run("command with stderr", func(t *testing.T) {
		task := structs.Task{Params: "ls /nonexistent_path_12345"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for ls nonexistent path, got %q", result.Status)
		}
	})

	t.Run("command with exit code 0 no output", func(t *testing.T) {
		task := structs.Task{Params: "true"}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "no output") {
			t.Errorf("expected 'no output' message: %s", result.Output)
		}
	})
}

// =============================================================================
// kill command tests (Linux-only)
// =============================================================================

func TestKillCommand(t *testing.T) {
	cmd := &KillCommand{}

	if cmd.Name() != "kill" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "kill")
	}

	t.Run("invalid JSON", func(t *testing.T) {
		task := structs.Task{Params: "not json"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for invalid JSON, got %q", result.Status)
		}
	})

	t.Run("zero PID", func(t *testing.T) {
		task := structs.Task{Params: `{"pid":0}`}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for zero PID, got %q", result.Status)
		}
	})

	t.Run("negative PID", func(t *testing.T) {
		task := structs.Task{Params: `{"pid":-1}`}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for negative PID, got %q", result.Status)
		}
	})

	t.Run("nonexistent PID", func(t *testing.T) {
		// Use a very high PID that's unlikely to exist
		task := structs.Task{Params: `{"pid":999999999}`}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent PID, got %q", result.Status)
		}
	})
}

// =============================================================================
// formatFileSize utility tests
// =============================================================================

func TestFormatFileSize(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{"zero bytes", 0, "0 B"},
		{"small bytes", 512, "512 B"},
		{"exactly 1KB", 1024, "1.0 KB"},
		{"kilobytes", 1536, "1.5 KB"},
		{"exactly 1MB", 1024 * 1024, "1.0 MB"},
		{"megabytes", 5 * 1024 * 1024, "5.0 MB"},
		{"exactly 1GB", 1024 * 1024 * 1024, "1.0 GB"},
		{"gigabytes", int64(2.5 * 1024 * 1024 * 1024), "2.5 GB"},
		{"1023 bytes", 1023, "1023 B"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatFileSize(tc.bytes)
			if result != tc.expected {
				t.Errorf("formatFileSize(%d) = %q, want %q", tc.bytes, result, tc.expected)
			}
		})
	}
}

// =============================================================================
// isMACAddress / containsMAC utility tests (from arp.go)
// =============================================================================

func TestIsMACAddress(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"00:11:22:33:44:55", true},
		{"aa:bb:cc:dd:ee:ff", true},
		{"AA:BB:CC:DD:EE:FF", true},
		{"00-11-22-33-44-55", true},
		{"not-a-mac", false},
		{"192.168.1.1", false},
		{"", false},
		{"00:11:22", false},
		{"00:11:22:33:44:55:66", false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := isMACAddress(tc.input)
			if result != tc.expected {
				t.Errorf("isMACAddress(%q) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

func TestContainsMAC(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"has colon MAC", "192.168.1.1  00:11:22:33:44:55  dynamic", true},
		{"has dash MAC", "192.168.1.1  00-11-22-33-44-55  dynamic", true},
		{"no MAC", "192.168.1.1  (incomplete)", false},
		{"empty", "", false},
		{"header line", "Interface: 192.168.1.1 --- 0x5", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := containsMAC(tc.input)
			if result != tc.expected {
				t.Errorf("containsMAC(%q) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

// =============================================================================
// knownService utility tests (from portscan.go)
// =============================================================================

func TestKnownService(t *testing.T) {
	tests := []struct {
		port     int
		expected string
	}{
		{22, "SSH"},
		{80, "HTTP"},
		{443, "HTTPS"},
		{445, "SMB"},
		{3389, "RDP"},
		{12345, ""},
		{0, ""},
	}

	for _, tc := range tests {
		result := knownService(tc.port)
		if result != tc.expected {
			t.Errorf("knownService(%d) = %q, want %q", tc.port, result, tc.expected)
		}
	}
}

// =============================================================================
// parseHosts utility tests (from portscan.go)
// =============================================================================

func TestParseHosts(t *testing.T) {
	t.Run("single IP", func(t *testing.T) {
		hosts, err := parseHosts("192.168.1.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(hosts) != 1 || hosts[0] != "192.168.1.1" {
			t.Errorf("expected [192.168.1.1], got %v", hosts)
		}
	})

	t.Run("multiple IPs", func(t *testing.T) {
		hosts, err := parseHosts("192.168.1.1,10.0.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(hosts) != 2 {
			t.Errorf("expected 2 hosts, got %d: %v", len(hosts), hosts)
		}
	})

	t.Run("IP range", func(t *testing.T) {
		hosts, err := parseHosts("192.168.1.1-5")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(hosts) != 5 {
			t.Errorf("expected 5 hosts, got %d: %v", len(hosts), hosts)
		}
	})

	t.Run("CIDR /30", func(t *testing.T) {
		hosts, err := parseHosts("192.168.1.0/30")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// /30 = 4 IPs, minus network and broadcast = 2 usable
		if len(hosts) != 2 {
			t.Errorf("expected 2 hosts for /30, got %d: %v", len(hosts), hosts)
		}
	})

	t.Run("hostname", func(t *testing.T) {
		hosts, err := parseHosts("myhost.local")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(hosts) != 1 || hosts[0] != "myhost.local" {
			t.Errorf("expected [myhost.local], got %v", hosts)
		}
	})

	t.Run("invalid CIDR", func(t *testing.T) {
		_, err := parseHosts("192.168.1.0/99")
		if err == nil {
			t.Error("expected error for invalid CIDR")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		hosts, err := parseHosts("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(hosts) != 0 {
			t.Errorf("expected 0 hosts for empty input, got %d", len(hosts))
		}
	})

	t.Run("range end before start", func(t *testing.T) {
		_, err := parseHosts("192.168.1.10-5")
		if err == nil {
			t.Error("expected error for range end < start")
		}
	})
}

// =============================================================================
// parsePorts utility tests (from portscan.go)
// =============================================================================

func TestParsePorts(t *testing.T) {
	t.Run("single port", func(t *testing.T) {
		ports, err := parsePorts("80")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ports) != 1 || ports[0] != 80 {
			t.Errorf("expected [80], got %v", ports)
		}
	})

	t.Run("multiple ports", func(t *testing.T) {
		ports, err := parsePorts("22,80,443")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ports) != 3 {
			t.Errorf("expected 3 ports, got %d: %v", len(ports), ports)
		}
	})

	t.Run("port range", func(t *testing.T) {
		ports, err := parsePorts("80-85")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ports) != 6 {
			t.Errorf("expected 6 ports (80-85), got %d: %v", len(ports), ports)
		}
	})

	t.Run("duplicate ports deduplicated", func(t *testing.T) {
		ports, err := parsePorts("80,80,80")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ports) != 1 {
			t.Errorf("expected 1 port after dedup, got %d: %v", len(ports), ports)
		}
	})

	t.Run("invalid port", func(t *testing.T) {
		_, err := parsePorts("abc")
		if err == nil {
			t.Error("expected error for non-numeric port")
		}
	})

	t.Run("port out of range", func(t *testing.T) {
		_, err := parsePorts("99999")
		if err == nil {
			t.Error("expected error for port > 65535")
		}
	})

	t.Run("reversed range", func(t *testing.T) {
		_, err := parsePorts("100-50")
		if err == nil {
			t.Error("expected error for reversed range")
		}
	})

	t.Run("range too large", func(t *testing.T) {
		_, err := parsePorts("1-60000")
		if err == nil {
			t.Error("expected error for range > 10000")
		}
	})

	t.Run("sorted output", func(t *testing.T) {
		ports, err := parsePorts("443,22,80")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ports[0] != 22 || ports[1] != 80 || ports[2] != 443 {
			t.Errorf("expected sorted [22,80,443], got %v", ports)
		}
	})
}

// =============================================================================
// isBroadcast utility test (from portscan.go)
// =============================================================================

func TestIsBroadcast(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")

	t.Run("broadcast address", func(t *testing.T) {
		ip := net.ParseIP("192.168.1.255").To4()
		if !isBroadcast(ip, ipNet) {
			t.Error("expected 192.168.1.255 to be broadcast for /24")
		}
	})

	t.Run("non-broadcast address", func(t *testing.T) {
		ip := net.ParseIP("192.168.1.100").To4()
		if isBroadcast(ip, ipNet) {
			t.Error("192.168.1.100 should not be broadcast")
		}
	})
}

// =============================================================================
// port-scan command integration tests
// =============================================================================

func TestPortScanCommand(t *testing.T) {
	cmd := &PortScanCommand{}

	if cmd.Name() != "port-scan" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "port-scan")
	}

	t.Run("empty params", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for empty params, got %q", result.Status)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		task := structs.Task{Params: "not json"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for invalid JSON, got %q", result.Status)
		}
	})

	t.Run("missing hosts", func(t *testing.T) {
		task := structs.Task{Params: `{"ports":"80"}`}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for missing hosts, got %q", result.Status)
		}
	})

	t.Run("scan localhost", func(t *testing.T) {
		// Scan a port that's definitely not open (high port, short timeout)
		task := structs.Task{Params: `{"hosts":"127.0.0.1","ports":"19999","timeout":1,"concurrency":1}`}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, "Scanned") {
			t.Errorf("expected 'Scanned' in output: %s", result.Output)
		}
	})
}

// =============================================================================
// download command basic tests (path parsing only, no file transfer)
// =============================================================================

func TestDownloadCommand(t *testing.T) {
	cmd := &DownloadCommand{}

	if cmd.Name() != "download" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "download")
	}

	t.Run("empty params", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for empty params, got %q", result.Status)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		task := structs.Task{Params: "/nonexistent/path/file.bin"}
		result := cmd.Execute(task)
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent file, got %q", result.Status)
		}
	})
}

// =============================================================================
// exit command basic test
// =============================================================================

func TestExitCommand(t *testing.T) {
	cmd := &ExitCommand{}

	if cmd.Name() != "exit" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "exit")
	}

	// Note: Can't test Execute() as it calls os.Exit
}

// =============================================================================
// Structs tests — Agent, Task, Job, CommandResult
// =============================================================================

func TestAgentUpdateSleepParams(t *testing.T) {
	agent := &structs.Agent{SleepInterval: 10, Jitter: 10}
	agent.UpdateSleepParams(30, 50)
	if agent.SleepInterval != 30 {
		t.Errorf("expected SleepInterval=30, got %d", agent.SleepInterval)
	}
	if agent.Jitter != 50 {
		t.Errorf("expected Jitter=50, got %d", agent.Jitter)
	}
}

func TestTaskStopFlag(t *testing.T) {
	task := structs.Task{ID: "test-1", Command: "test"}
	if task.DidStop() {
		t.Error("new task should not be stopped")
	}
	if task.ShouldStop() {
		t.Error("new task ShouldStop should be false")
	}
	task.SetStop()
	if !task.DidStop() {
		t.Error("after SetStop, DidStop should be true")
	}
	if !task.ShouldStop() {
		t.Error("after SetStop, ShouldStop should be true")
	}
}

func TestTaskNewResponse(t *testing.T) {
	task := structs.Task{ID: "task-123"}
	resp := task.NewResponse()
	if resp.TaskID != "task-123" {
		t.Errorf("expected TaskID=task-123, got %q", resp.TaskID)
	}
}

func TestJobFileTransferMethods(t *testing.T) {
	job := &structs.Job{
		FileTransfers: make(map[string]chan json.RawMessage),
	}

	// Set a file transfer channel
	ch := make(chan json.RawMessage, 1)
	job.SetFileTransfer("test-uuid", ch)

	// Get it back
	gotCh, ok := job.GetFileTransfer("test-uuid")
	if !ok {
		t.Fatal("expected to find file transfer channel")
	}
	if gotCh != ch {
		t.Error("returned channel doesn't match set channel")
	}

	// Get nonexistent
	_, ok = job.GetFileTransfer("nonexistent")
	if ok {
		t.Error("expected ok=false for nonexistent key")
	}

	// Broadcast test
	ch2 := make(chan json.RawMessage, 1)
	job.SetFileTransfer("test-uuid-2", ch2)

	data := json.RawMessage(`{"test":"data"}`)
	job.BroadcastFileTransfer(data)

	select {
	case got := <-ch:
		if string(got) != `{"test":"data"}` {
			t.Errorf("broadcast data mismatch: %s", got)
		}
	default:
		t.Error("expected data on channel 1 after broadcast")
	}

	select {
	case got := <-ch2:
		if string(got) != `{"test":"data"}` {
			t.Errorf("broadcast data mismatch on ch2: %s", got)
		}
	default:
		t.Error("expected data on channel 2 after broadcast")
	}
}

// =============================================================================
// av-detect command tests
// =============================================================================

func TestAvDetectCommand(t *testing.T) {
	cmd := &AvDetectCommand{}

	if cmd.Name() != "av-detect" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "av-detect")
	}

	t.Run("basic execution", func(t *testing.T) {
		task := structs.Task{Params: ""}
		result := cmd.Execute(task)
		if result.Status != "success" {
			t.Errorf("expected success, got %q: %s", result.Status, result.Output)
		}
		if !result.Completed {
			t.Error("expected completed=true")
		}
		// Output should be valid JSON (either "[]" or an array of detected products)
		if result.Output != "[]" {
			var detected []detectedProduct
			if err := json.Unmarshal([]byte(result.Output), &detected); err != nil {
				t.Errorf("output is not valid JSON: %v, output: %s", err, result.Output)
			}
		}
	})

	t.Run("known process database populated", func(t *testing.T) {
		// Verify the database contains entries for major vendors
		vendors := make(map[string]bool)
		for _, product := range knownSecurityProcesses {
			vendors[product.Vendor] = true
		}

		expectedVendors := []string{"Microsoft", "CrowdStrike", "SentinelOne", "Sophos", "Kaspersky", "ESET"}
		for _, v := range expectedVendors {
			if !vendors[v] {
				t.Errorf("missing vendor in database: %s", v)
			}
		}
	})

	t.Run("database categories valid", func(t *testing.T) {
		validCategories := map[string]bool{"AV": true, "EDR": true, "Firewall": true, "HIPS": true, "DLP": true, "Logging": true}
		for name, product := range knownSecurityProcesses {
			if !validCategories[product.Category] {
				t.Errorf("invalid category %q for process %q", product.Category, name)
			}
		}
	})

	t.Run("database keys are lowercase", func(t *testing.T) {
		for name := range knownSecurityProcesses {
			if name != strings.ToLower(name) {
				t.Errorf("database key %q is not lowercase", name)
			}
		}
	})
}
