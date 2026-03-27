//go:build linux

package commands

import (
	"encoding/binary"
	"os"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// Linux utmp record structure
const (
	utmpUserSize = 32
	utmpLineSize = 32
	utmpHostSize = 256
	utmpRecSize  = 384 // Approximate size, may vary
	utUserProc   = 7   // Normal process
	utDeadProc   = 8   // Terminated
)

func lastPlatform(args lastArgs) []lastLoginEntry {
	// Try wtmp first (historical logins), then utmp (current)
	files := []string{"/var/log/wtmp", "/var/run/utmp"}
	var entries []lastLoginEntry

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		recSize := detectRecordSize(data)
		if recSize == 0 {
			structs.ZeroBytes(data)
			continue
		}

		numRecords := len(data) / recSize
		for i := numRecords - 1; i >= 0 && len(entries) < args.Count; i-- {
			offset := i * recSize
			if offset+recSize > len(data) {
				continue
			}
			rec := data[offset : offset+recSize]

			utType := binary.LittleEndian.Uint32(rec[0:4])
			if utType != utUserProc {
				continue
			}

			line := extractCString(rec[8:40])
			user := extractCString(rec[44:76])
			host := extractCString(rec[76:332])

			var loginTime time.Time
			if recSize >= 384 {
				tvSec := int64(binary.LittleEndian.Uint32(rec[340:344]))
				loginTime = time.Unix(tvSec, 0)
			}

			if args.User != "" && !strings.EqualFold(user, args.User) {
				continue
			}

			if host == "" {
				host = "-"
			}
			if line == "" {
				line = "-"
			}

			entries = append(entries, lastLoginEntry{
				User:      user,
				TTY:       line,
				From:      host,
				LoginTime: loginTime.Format("2006-01-02 15:04:05"),
			})
		}

		structs.ZeroBytes(data)

		if len(entries) > 0 {
			break
		}
	}

	// Fallback: parse auth.log entries as raw text
	if len(entries) == 0 {
		entries = lastFromAuthLogEntries(args)
	}

	return entries
}

func detectRecordSize(data []byte) int {
	// Common sizes: 384 (64-bit), 292 (32-bit)
	for _, size := range []int{384, 392, 288, 292} {
		if len(data) >= size && len(data)%size == 0 {
			return size
		}
	}
	// Try 384 as default
	if len(data) >= 384 {
		return 384
	}
	return 0
}

func extractCString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

// lastFailedPlatform parses /var/log/btmp for failed login attempts (newest first).
// btmp uses the same utmp binary record format as wtmp.
func lastFailedPlatform(args lastArgs) []lastLoginEntry {
	data, err := os.ReadFile("/var/log/btmp")
	if err != nil {
		// btmp requires root; fall back to auth.log parsing
		return lastFailedFromAuthLog(args)
	}
	defer structs.ZeroBytes(data)

	recSize := detectRecordSize(data)
	if recSize == 0 {
		structs.ZeroBytes(data)
		return lastFailedFromAuthLog(args)
	}

	var entries []lastLoginEntry
	numRecords := len(data) / recSize
	for i := numRecords - 1; i >= 0 && len(entries) < args.Count; i-- {
		offset := i * recSize
		if offset+recSize > len(data) {
			continue
		}
		rec := data[offset : offset+recSize]

		// utmp offsets: user@44(32), line@8(32), host@76(256), tv_sec@340
		user := extractCString(rec[44 : 44+utmpUserSize])
		line := extractCString(rec[8 : 8+utmpLineSize])
		host := extractCString(rec[76 : 76+utmpHostSize])

		var loginTime time.Time
		if recSize >= 384 {
			tvSec := int64(binary.LittleEndian.Uint32(rec[340:344]))
			loginTime = time.Unix(tvSec, 0)
		}

		if user == "" {
			continue
		}
		if args.User != "" && !strings.EqualFold(user, args.User) {
			continue
		}
		if host == "" {
			host = "-"
		}
		if line == "" {
			line = "-"
		}

		entries = append(entries, lastLoginEntry{
			User:      user,
			TTY:       line,
			From:      host,
			LoginTime: loginTime.Format("2006-01-02 15:04:05"),
			Duration:  "FAILED",
		})
	}

	if len(entries) == 0 {
		return lastFailedFromAuthLog(args)
	}

	return entries
}

// lastFailedFromAuthLog parses auth.log/secure for failed login lines.
func lastFailedFromAuthLog(args lastArgs) []lastLoginEntry {
	var entries []lastLoginEntry

	logFiles := []string{"/var/log/auth.log", "/var/log/secure"}
	for _, logFile := range logFiles {
		data, err := os.ReadFile(logFile)
		if err != nil {
			continue
		}

		lines := strings.Split(string(data), "\n")
		structs.ZeroBytes(data)
		for i := len(lines) - 1; i >= 0 && len(entries) < args.Count; i-- {
			line := lines[i]
			if !strings.Contains(line, "Failed password") && !strings.Contains(line, "authentication failure") {
				continue
			}
			if args.User != "" && !strings.Contains(line, args.User) {
				continue
			}
			entries = append(entries, lastLoginEntry{
				User:      line,
				LoginTime: "-",
				Duration:  "FAILED",
			})
		}
		if len(entries) > 0 {
			break
		}
	}

	return entries
}

// lastRebootPlatform parses /var/log/wtmp for boot/shutdown events (newest first).
// BOOT_TIME (ut_type=2) records system boot. RUN_LVL (ut_type=1) with "shutdown"
// in ut_line records clean shutdowns.
func lastRebootPlatform(args lastArgs) []lastLoginEntry {
	data, err := os.ReadFile("/var/log/wtmp")
	if err != nil {
		return nil
	}
	defer structs.ZeroBytes(data)

	recSize := detectRecordSize(data)
	if recSize == 0 {
		return nil
	}

	const (
		utRunLvl   = 1
		utBootTime = 2
	)

	var entries []lastLoginEntry
	numRecords := len(data) / recSize
	for i := numRecords - 1; i >= 0 && len(entries) < args.Count; i-- {
		offset := i * recSize
		if offset+recSize > len(data) {
			continue
		}
		rec := data[offset : offset+recSize]

		utType := binary.LittleEndian.Uint32(rec[0:4])

		var eventType string
		switch utType {
		case utBootTime:
			eventType = "boot"
		case utRunLvl:
			line := extractCString(rec[8:40])
			if strings.Contains(strings.ToLower(line), "shutdown") {
				eventType = "shutdown"
			} else {
				continue
			}
		default:
			continue
		}

		var eventTime time.Time
		if recSize >= 384 {
			tvSec := int64(binary.LittleEndian.Uint32(rec[340:344]))
			eventTime = time.Unix(tvSec, 0)
		}

		user := extractCString(rec[44:76])
		if user == "" {
			user = "system"
		}

		entries = append(entries, lastLoginEntry{
			User:      user,
			TTY:       eventType,
			From:      "-",
			LoginTime: eventTime.Format("2006-01-02 15:04:05"),
		})
	}

	return entries
}

func lastFromAuthLogEntries(args lastArgs) []lastLoginEntry {
	var entries []lastLoginEntry

	logFiles := []string{"/var/log/auth.log", "/var/log/secure"}
	for _, logFile := range logFiles {
		data, err := os.ReadFile(logFile)
		if err != nil {
			continue
		}

		lines := strings.Split(string(data), "\n")
		structs.ZeroBytes(data)
		for i := len(lines) - 1; i >= 0 && len(entries) < args.Count; i-- {
			line := lines[i]
			if !strings.Contains(line, "session opened") && !strings.Contains(line, "Accepted") {
				continue
			}
			if args.User != "" && !strings.Contains(line, args.User) {
				continue
			}
			entries = append(entries, lastLoginEntry{
				User:      line,
				LoginTime: "-",
			})
		}
		if len(entries) > 0 {
			break
		}
	}

	return entries
}
