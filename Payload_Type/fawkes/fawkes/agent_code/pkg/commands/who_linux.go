//go:build linux
// +build linux

package commands

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	whoUtmpUserProcess = 7
	whoUtmpRecordSize  = 384 // sizeof(struct utmp) on x86_64 Linux
)

func whoPlatform(args whoArgs) string {
	// Parse /var/run/utmp for currently logged-in users
	data, err := os.ReadFile("/var/run/utmp")
	if err != nil {
		// Fallback: try /run/utmp
		data, err = os.ReadFile("/run/utmp")
		if err != nil {
			return fmt.Sprintf("Error reading utmp: %v", err)
		}
	}

	var sb strings.Builder
	sb.WriteString(whoHeader())

	count := 0
	for i := 0; i+whoUtmpRecordSize <= len(data); i += whoUtmpRecordSize {
		record := data[i : i+whoUtmpRecordSize]

		utType := int32(binary.LittleEndian.Uint32(record[0:4]))

		// Only show USER_PROCESS entries unless -all
		if !args.All && utType != whoUtmpUserProcess {
			continue
		}

		user := strings.TrimRight(string(record[4:36]), "\x00")
		tty := strings.TrimRight(string(record[36:68]), "\x00")
		host := strings.TrimRight(string(record[76:332]), "\x00")

		// Login time: tv_sec at offset 340 (4 bytes)
		tvSec := int64(binary.LittleEndian.Uint32(record[340:344]))
		loginTime := time.Unix(tvSec, 0).Format("2006-01-02 15:04:05")

		if user == "" && !args.All {
			continue
		}

		status := "active"
		if utType != whoUtmpUserProcess {
			status = fmt.Sprintf("type=%d", utType)
		}

		sb.WriteString(whoEntry(user, tty, loginTime, host, status))
		count++
	}

	if count == 0 {
		return "No active user sessions found"
	}

	sb.WriteString(fmt.Sprintf("\n[*] %d active session(s)", count))
	return sb.String()
}
