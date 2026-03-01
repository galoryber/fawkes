//go:build darwin
// +build darwin

package commands

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func uptimePlatform() string {
	// Use sysctl kern.boottime
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return fmt.Sprintf("Error getting boot time: %v", err)
	}

	bootTime := time.Unix(tv.Sec, int64(tv.Usec)*1000)
	uptimeSecs := int64(time.Since(bootTime).Seconds())

	var sb strings.Builder
	sb.WriteString("[*] System Uptime\n")
	sb.WriteString(fmt.Sprintf("  Uptime:    %s\n", formatUptime(uptimeSecs)))
	sb.WriteString(fmt.Sprintf("  Boot time: %s\n", bootTime.Format("2006-01-02 15:04:05 MST")))

	return sb.String()
}
