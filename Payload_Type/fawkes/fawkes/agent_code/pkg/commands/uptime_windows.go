//go:build windows
// +build windows

package commands

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

var (
	kernel32UT           = windows.NewLazySystemDLL("kernel32.dll")
	procGetTickCount64UT = kernel32UT.NewProc("GetTickCount64")
)

func uptimePlatform() string {
	// GetTickCount64 returns milliseconds since system start directly in ret
	ret, _, _ := procGetTickCount64UT.Call()
	uptimeMs := uint64(ret)
	uptimeSecs := int64(uptimeMs / 1000)

	bootTime := time.Now().Add(-time.Duration(uptimeMs) * time.Millisecond)

	var sb strings.Builder
	sb.WriteString("[*] System Uptime\n")
	sb.WriteString(fmt.Sprintf("  Uptime:    %s\n", formatUptime(uptimeSecs)))
	sb.WriteString(fmt.Sprintf("  Boot time: %s\n", bootTime.Format("2006-01-02 15:04:05 MST")))

	return sb.String()
}
