//go:build darwin

package commands

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

const (
	whoUtmpxRecordSize  = 628
	whoUtmpxUserProcess = 7
)

// whoUtmpxPath can be overridden in tests.
var whoUtmpxPath = "/var/run/utmpx"

func whoPlatform(args whoArgs) []whoSessionEntry {
	data, err := os.ReadFile(whoUtmpxPath)
	if err != nil {
		return nil
	}
	defer structs.ZeroBytes(data)

	var entries []whoSessionEntry
	for offset := 0; offset+whoUtmpxRecordSize <= len(data); offset += whoUtmpxRecordSize {
		rec := data[offset : offset+whoUtmpxRecordSize]

		utType := int16(binary.LittleEndian.Uint16(rec[296:298]))

		if !args.All && utType != whoUtmpxUserProcess {
			continue
		}

		user := extractCString(rec[0:256])
		tty := extractCString(rec[260:292])
		host := extractCString(rec[308:564])
		tvSec := int64(binary.LittleEndian.Uint32(rec[300:304]))
		loginTime := time.Unix(tvSec, 0).Format("2006-01-02 15:04:05")

		if user == "" && !args.All {
			continue
		}

		status := "active"
		if utType != whoUtmpxUserProcess {
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
			From:      strings.TrimSpace(host),
			Status:    status,
		})
	}

	return entries
}
