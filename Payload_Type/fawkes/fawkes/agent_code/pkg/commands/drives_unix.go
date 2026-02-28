//go:build !windows

package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"fawkes/pkg/structs"
)

type driveEntry struct {
	Drive   string  `json:"drive"`
	Type    string  `json:"type"`
	Label   string  `json:"label"`
	FreeGB  float64 `json:"free_gb"`
	TotalGB float64 `json:"total_gb"`
}

// DrivesUnixCommand implements the drives command for Linux and macOS.
type DrivesUnixCommand struct{}

func (c *DrivesUnixCommand) Name() string {
	return "drives"
}

func (c *DrivesUnixCommand) Description() string {
	return "List mounted filesystems with type and free space (T1083)"
}

func (c *DrivesUnixCommand) Execute(task structs.Task) structs.CommandResult {
	mounts := getMountPoints()
	if len(mounts) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	var entries []driveEntry
	for _, m := range mounts {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(m.mountPoint, &stat); err != nil {
			continue
		}

		totalBytes := uint64(stat.Blocks) * uint64(stat.Bsize)
		freeBytes := uint64(stat.Bavail) * uint64(stat.Bsize)

		entries = append(entries, driveEntry{
			Drive:   m.mountPoint,
			Type:    m.fsType,
			Label:   m.device,
			FreeGB:  float64(freeBytes) / (1024 * 1024 * 1024),
			TotalGB: float64(totalBytes) / (1024 * 1024 * 1024),
		})
	}

	if len(entries) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	jsonBytes, err := json.Marshal(entries)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshalling drive data: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(jsonBytes),
		Status:    "success",
		Completed: true,
	}
}

type mountEntry struct {
	device     string
	mountPoint string
	fsType     string
}

func getMountPoints() []mountEntry {
	// Try /proc/mounts first (Linux)
	if mounts := parseProcMounts(); len(mounts) > 0 {
		return mounts
	}
	// Fall back to mount command (macOS)
	return parseMountCommand()
}

func parseProcMounts() []mountEntry {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil
	}
	defer f.Close()

	var mounts []mountEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if shouldSkipFs(fields[2], fields[0]) {
			continue
		}
		mounts = append(mounts, mountEntry{
			device:     fields[0],
			mountPoint: fields[1],
			fsType:     fields[2],
		})
	}
	return mounts
}

func parseMountCommand() []mountEntry {
	out, err := exec.Command("mount").Output()
	if err != nil {
		return nil
	}

	var mounts []mountEntry
	for _, line := range strings.Split(string(out), "\n") {
		// macOS format: /dev/disk1s1 on / (apfs, local, journaled)
		parts := strings.SplitN(line, " on ", 2)
		if len(parts) != 2 {
			continue
		}
		device := parts[0]
		rest := parts[1]

		parenIdx := strings.LastIndex(rest, " (")
		if parenIdx < 0 {
			continue
		}
		mountPoint := rest[:parenIdx]
		optStr := strings.TrimSuffix(rest[parenIdx+2:], ")")
		opts := strings.Split(optStr, ", ")
		fsType := ""
		if len(opts) > 0 {
			fsType = opts[0]
		}

		if shouldSkipFs(fsType, device) {
			continue
		}
		mounts = append(mounts, mountEntry{
			device:     device,
			mountPoint: mountPoint,
			fsType:     fsType,
		})
	}
	return mounts
}

// shouldSkipFs filters out pseudo-filesystems and kernel virtual mounts.
func shouldSkipFs(fsType, device string) bool {
	skipTypes := map[string]bool{
		"proc": true, "sysfs": true, "devpts": true, "devtmpfs": true,
		"cgroup": true, "cgroup2": true, "pstore": true, "securityfs": true,
		"debugfs": true, "tracefs": true, "hugetlbfs": true, "mqueue": true,
		"configfs": true, "fusectl": true, "binfmt_misc": true, "rpc_pipefs": true,
		"nfsd": true, "autofs": true, "bpf": true, "efivarfs": true,
	}
	if skipTypes[fsType] {
		return true
	}
	if device == "none" || device == "systemd-1" || strings.HasPrefix(device, "cgroup") {
		return true
	}
	return false
}

