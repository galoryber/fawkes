package commands

import (
	"bufio"
	"os"
	"strings"
	"syscall"
)

func getDiskFreeInfo() ([]dfEntry, error) {
	// Parse /proc/mounts to get filesystem list
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []dfEntry
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		device := fields[0]
		mountpoint := fields[1]
		fstype := fields[2]

		// Skip virtual/pseudo filesystems
		if strings.HasPrefix(fstype, "sys") || strings.HasPrefix(fstype, "proc") ||
			fstype == "devtmpfs" || fstype == "devpts" || fstype == "securityfs" ||
			fstype == "cgroup" || fstype == "cgroup2" || fstype == "pstore" ||
			fstype == "debugfs" || fstype == "tracefs" || fstype == "hugetlbfs" ||
			fstype == "mqueue" || fstype == "fusectl" || fstype == "configfs" ||
			fstype == "binfmt_misc" || fstype == "autofs" || fstype == "efivarfs" ||
			fstype == "bpf" || fstype == "nsfs" {
			continue
		}

		// Deduplicate by mountpoint
		if seen[mountpoint] {
			continue
		}
		seen[mountpoint] = true

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountpoint, &stat); err != nil {
			continue
		}

		total := stat.Blocks * uint64(stat.Bsize)
		avail := stat.Bavail * uint64(stat.Bsize)
		free := stat.Bfree * uint64(stat.Bsize)
		used := total - free

		entries = append(entries, dfEntry{
			device:     device,
			fstype:     fstype,
			mountpoint: mountpoint,
			total:      total,
			used:       used,
			avail:      avail,
		})
	}

	return entries, nil
}
