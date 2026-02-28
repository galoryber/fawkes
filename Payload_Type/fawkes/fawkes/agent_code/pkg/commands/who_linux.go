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

func whoPlatform(args whoArgs) []whoSessionEntry {
	data, err := os.ReadFile("/var/run/utmp")
	if err != nil {
		data, err = os.ReadFile("/run/utmp")
		if err != nil {
			return nil
		}
	}

	var entries []whoSessionEntry
	for i := 0; i+whoUtmpRecordSize <= len(data); i += whoUtmpRecordSize {
		record := data[i : i+whoUtmpRecordSize]
		utType := int32(binary.LittleEndian.Uint32(record[0:4]))

		if !args.All && utType != whoUtmpUserProcess {
			continue
		}

		user := strings.TrimRight(string(record[4:36]), "\x00")
		tty := strings.TrimRight(string(record[36:68]), "\x00")
		host := strings.TrimRight(string(record[76:332]), "\x00")
		tvSec := int64(binary.LittleEndian.Uint32(record[340:344]))
		loginTime := time.Unix(tvSec, 0).Format("2006-01-02 15:04:05")

		if user == "" && !args.All {
			continue
		}

		status := "active"
		if utType != whoUtmpUserProcess {
			status = fmt.Sprintf("type=%d", utType)
		}
		if host == "" {
			host = "-"
		}
		if tty == "" {
			tty = "-"
		}

		entries = append(entries, whoSessionEntry{
			User:      user,
			TTY:       tty,
			LoginTime: loginTime,
			From:      host,
			Status:    status,
		})
	}

	return entries
}
