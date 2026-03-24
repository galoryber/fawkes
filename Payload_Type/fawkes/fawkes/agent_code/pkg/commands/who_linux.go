//go:build linux

package commands

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"fawkes/pkg/structs"
)

func whoPlatform(args whoArgs) []whoSessionEntry {
	data, err := os.ReadFile("/var/run/utmp")
	if err != nil {
		data, err = os.ReadFile("/run/utmp")
		if err != nil {
			return nil
		}
	}
	defer structs.ZeroBytes(data)

	var entries []whoSessionEntry
	for i := 0; i+utmpRecordSize <= len(data); i += utmpRecordSize {
		record := data[i : i+utmpRecordSize]
		utType := int32(binary.LittleEndian.Uint32(record[0:4]))

		if !args.All && utType != utUserProc {
			continue
		}

		// Correct Linux x86_64 utmp offsets:
		// ut_line at 8 (32 bytes), ut_user at 44 (32 bytes), ut_host at 76 (256 bytes)
		user := extractCString(record[44 : 44+utmpUserSize])
		tty := extractCString(record[8 : 8+utmpLineSize])
		host := extractCString(record[76 : 76+utmpHostSize])
		tvSec := int64(binary.LittleEndian.Uint32(record[340:344]))
		loginTime := time.Unix(tvSec, 0).Format("2006-01-02 15:04:05")

		if user == "" && !args.All {
			continue
		}

		status := "active"
		if utType != utUserProc {
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
