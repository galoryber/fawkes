//go:build linux

package commands

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"
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

func lastPlatform(args lastArgs) string {
	var sb strings.Builder
	sb.WriteString("=== Login History ===\n\n")
	sb.WriteString(lastHeader())

	// Try wtmp first (historical logins), then utmp (current)
	files := []string{"/var/log/wtmp", "/var/run/utmp"}
	count := 0

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		// Parse utmp/wtmp records (backwards for most recent first)
		recSize := detectRecordSize(data)
		if recSize == 0 {
			continue
		}

		numRecords := len(data) / recSize
		for i := numRecords - 1; i >= 0 && count < args.Count; i-- {
			offset := i * recSize
			if offset+recSize > len(data) {
				continue
			}
			rec := data[offset : offset+recSize]

			// utmp struct: type(4) + pid(4) + line(32) + id(4) + user(32) + host(256) + ... + tv_sec(4/8)
			utType := binary.LittleEndian.Uint32(rec[0:4])
			if utType != utUserProc {
				continue
			}

			line := extractCString(rec[8:40])
			user := extractCString(rec[44:76])
			host := extractCString(rec[76:332])

			// Timestamp is at different offsets depending on arch
			var loginTime time.Time
			if recSize >= 384 {
				tvSec := int64(binary.LittleEndian.Uint32(rec[340:344]))
				loginTime = time.Unix(tvSec, 0)
			}

			if args.User != "" && !strings.EqualFold(user, args.User) {
				continue
			}

			sb.WriteString(formatLastEntry(user, line, host,
				loginTime.Format("2006-01-02 15:04:05"), ""))
			count++
		}

		if count > 0 {
			break // Got records from wtmp, no need for utmp
		}
	}

	// Fallback: parse /var/log/auth.log or /var/log/secure
	if count == 0 {
		sb.WriteString(lastFromAuthLog(args))
	}

	sb.WriteString(fmt.Sprintf("\n%d entries shown", count))
	return sb.String()
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

func lastFromAuthLog(args lastArgs) string {
	var sb strings.Builder

	logFiles := []string{"/var/log/auth.log", "/var/log/secure"}
	for _, logFile := range logFiles {
		data, err := os.ReadFile(logFile)
		if err != nil {
			continue
		}

		lines := strings.Split(string(data), "\n")
		count := 0
		// Read backwards
		for i := len(lines) - 1; i >= 0 && count < args.Count; i-- {
			line := lines[i]
			if !strings.Contains(line, "session opened") && !strings.Contains(line, "Accepted") {
				continue
			}
			if args.User != "" && !strings.Contains(line, args.User) {
				continue
			}
			sb.WriteString(fmt.Sprintf("  %s\n", line))
			count++
		}
		if count > 0 {
			break
		}
	}

	return sb.String()
}
