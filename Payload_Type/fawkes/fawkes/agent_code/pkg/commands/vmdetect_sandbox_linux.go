//go:build linux

package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// sandboxCheckUptime checks system uptime — very low uptime suggests a sandbox.
func sandboxCheckUptime() sandboxCheck {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return sandboxCheck{Name: "System Uptime", Category: "timing", Details: "error: " + err.Error()}
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return sandboxCheck{Name: "System Uptime", Category: "timing", Details: "parse error"}
	}

	uptimeSec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return sandboxCheck{Name: "System Uptime", Category: "timing", Details: "parse error: " + err.Error()}
	}

	uptime := time.Duration(uptimeSec * float64(time.Second))
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
		Details:    uptime.Truncate(time.Second).String(),
	}
}

// sandboxCheckRAM checks total RAM — sandboxes often have minimal RAM.
func sandboxCheckRAM() sandboxCheck {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return sandboxCheck{Name: "Total RAM", Category: "hardware", Details: "error: " + err.Error()}
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kbStr := fields[1]
				kb, err := strconv.ParseUint(kbStr, 10, 64)
				if err == nil {
					gb := float64(kb) / (1024 * 1024)
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
			}
		}
	}

	return sandboxCheck{Name: "Total RAM", Category: "hardware", Details: "unable to determine"}
}

// sandboxCheckDisk checks total disk space — sandboxes often have small disks.
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

// countProcesses counts running processes via /proc.
func countProcesses() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			name := e.Name()
			if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
				count++
			}
		}
	}
	return count
}
