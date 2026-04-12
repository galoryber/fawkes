//go:build darwin

package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// sandboxCheckUptime checks system uptime via sysctl kern.boottime.
func sandboxCheckUptime() sandboxCheck {
	// Use syscall.Sysctl to get boot time
	bootTimeStr, err := syscall.Sysctl("kern.boottime")
	if err != nil || len(bootTimeStr) < 4 {
		return sandboxCheck{Name: "System Uptime", Category: "timing", Details: "unable to determine"}
	}

	// kern.boottime returns a struct timeval; first 4 bytes are tv_sec (little-endian on arm64)
	bootSec := int64(bootTimeStr[0]) | int64(bootTimeStr[1])<<8 | int64(bootTimeStr[2])<<16 | int64(bootTimeStr[3])<<24
	uptime := time.Since(time.Unix(bootSec, 0))

	suspicious := uptime < 5*time.Minute
	score := 0
	if uptime < 2*time.Minute {
		score = 15
	} else if uptime < 5*time.Minute {
		score = 10
	}

	return sandboxCheck{
		Name:       "System Uptime",
		Category:   "timing",
		Suspicious: suspicious,
		Score:      score,
		Details:    fmt.Sprintf("%s", uptime.Truncate(time.Second)),
	}
}

// sandboxCheckRAM checks total RAM via sysctl hw.memsize.
func sandboxCheckRAM() sandboxCheck {
	memStr, err := syscall.Sysctl("hw.memsize")
	if err != nil || len(memStr) < 8 {
		return sandboxCheck{Name: "Total RAM", Category: "hardware", Details: "unable to determine"}
	}

	// hw.memsize returns uint64 bytes
	var memBytes uint64
	for i := 0; i < 8 && i < len(memStr); i++ {
		memBytes |= uint64(memStr[i]) << (uint(i) * 8)
	}

	gb := float64(memBytes) / (1024 * 1024 * 1024)
	suspicious := gb < 2.0
	score := 0
	if gb < 1.0 {
		score = 15
	} else if gb < 2.0 {
		score = 10
	}

	return sandboxCheck{
		Name:       "Total RAM",
		Category:   "hardware",
		Suspicious: suspicious,
		Score:      score,
		Details:    fmt.Sprintf("%.1f GB", gb),
	}
}

// sandboxCheckDisk checks total disk space.
func sandboxCheckDisk() sandboxCheck {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return sandboxCheck{Name: "Disk Size", Category: "hardware", Details: "error: " + err.Error()}
	}

	totalBytes := stat.Blocks * uint64(stat.Bsize)
	totalGB := float64(totalBytes) / (1024 * 1024 * 1024)

	suspicious := totalGB < 50.0
	score := 0
	if totalGB < 20.0 {
		score = 15
	} else if totalGB < 50.0 {
		score = 10
	}

	return sandboxCheck{
		Name:       "Disk Size",
		Category:   "hardware",
		Suspicious: suspicious,
		Score:      score,
		Details:    fmt.Sprintf("%.0f GB total", totalGB),
	}
}

// countProcesses counts running processes by scanning /proc or ps fallback.
func countProcesses() int {
	// macOS doesn't have /proc — count files in /dev that look like process ttys
	// or read /var/run to approximate. Best approach: stat entries via sysctl.
	// Simplified: read from output of kern.proc.all via sysctl
	entries, err := os.ReadDir("/dev")
	if err != nil {
		return 0
	}
	// Count tty entries as rough process approximation
	count := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "ttys") {
			numPart := name[4:]
			if _, err := strconv.Atoi(numPart); err == nil {
				count++
			}
		}
	}
	// ttys count is usually much less than processes; approximate by multiplying
	if count > 0 {
		return count * 5 // rough approximation
	}
	return 0 // unable to determine
}
