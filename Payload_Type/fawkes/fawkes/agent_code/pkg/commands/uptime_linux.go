//go:build linux
// +build linux

package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func uptimePlatform() string {
	// Read /proc/uptime: first field is uptime in seconds (float)
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return fmt.Sprintf("Error reading /proc/uptime: %v", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return "Error: unexpected /proc/uptime format"
	}

	uptimeFloat, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return fmt.Sprintf("Error parsing uptime: %v", err)
	}

	uptimeSecs := int64(uptimeFloat)
	bootTime := time.Now().Add(-time.Duration(uptimeSecs) * time.Second)

	var sb strings.Builder
	sb.WriteString("[*] System Uptime\n")
	sb.WriteString(fmt.Sprintf("  Uptime:    %s\n", formatUptime(uptimeSecs)))
	sb.WriteString(fmt.Sprintf("  Boot time: %s\n", bootTime.Format("2006-01-02 15:04:05 MST")))

	// Also check load averages from /proc/loadavg
	loadData, err := os.ReadFile("/proc/loadavg")
	if err == nil {
		loadFields := strings.Fields(string(loadData))
		if len(loadFields) >= 3 {
			sb.WriteString(fmt.Sprintf("  Load avg:  %s %s %s (1m 5m 15m)\n", loadFields[0], loadFields[1], loadFields[2]))
		}
	}

	return sb.String()
}
