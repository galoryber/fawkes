package commands

// procdump_helpers.go — Cross-platform helpers for process memory dump parsing.
// No build constraints so these functions can be tested on CI.

import (
	"fmt"
	"strconv"
	"strings"
)

// procdumpArgs is the shared parameter struct for procdump across platforms.
type procdumpArgs struct {
	Action string `json:"action"`
	PID    int    `json:"pid"`
}

// memoryRegion represents a parsed entry from /proc/<pid>/maps.
type memoryRegion struct {
	Start    uint64
	End      uint64
	Perms    string // e.g., "r-xp", "rw-p"
	Offset   uint64
	Dev      string // e.g., "08:01"
	Inode    uint64
	Pathname string // e.g., "/usr/bin/ls", "[heap]", "[stack]", ""
}

// Size returns the size of the memory region in bytes.
func (r memoryRegion) Size() uint64 {
	return r.End - r.Start
}

// IsReadable returns true if the region has read permission.
func (r memoryRegion) IsReadable() bool {
	return len(r.Perms) >= 1 && r.Perms[0] == 'r'
}

// IsWritable returns true if the region has write permission.
func (r memoryRegion) IsWritable() bool {
	return len(r.Perms) >= 2 && r.Perms[1] == 'w'
}

// IsPrivate returns true if the region is private (copy-on-write).
func (r memoryRegion) IsPrivate() bool {
	return len(r.Perms) >= 4 && r.Perms[3] == 'p'
}

// IsAnonymous returns true if the region has no backing file (anonymous mapping).
func (r memoryRegion) IsAnonymous() bool {
	return r.Pathname == ""
}

// parseMapsLine parses a single line from /proc/<pid>/maps.
// Format: "start-end perms offset dev inode pathname"
// Example: "7f8a1c000000-7f8a1c021000 rw-p 00000000 00:00 0                          [heap]"
func parseMapsLine(line string) (memoryRegion, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return memoryRegion{}, fmt.Errorf("empty line")
	}

	fields := strings.Fields(line)
	if len(fields) < 5 {
		return memoryRegion{}, fmt.Errorf("too few fields: %d", len(fields))
	}

	// Parse address range "start-end"
	addrParts := strings.SplitN(fields[0], "-", 2)
	if len(addrParts) != 2 {
		return memoryRegion{}, fmt.Errorf("invalid address range: %s", fields[0])
	}

	start, err := strconv.ParseUint(addrParts[0], 16, 64)
	if err != nil {
		return memoryRegion{}, fmt.Errorf("invalid start address: %v", err)
	}

	end, err := strconv.ParseUint(addrParts[1], 16, 64)
	if err != nil {
		return memoryRegion{}, fmt.Errorf("invalid end address: %v", err)
	}

	perms := fields[1]

	offset, err := strconv.ParseUint(fields[2], 16, 64)
	if err != nil {
		return memoryRegion{}, fmt.Errorf("invalid offset: %v", err)
	}

	dev := fields[3]

	inode, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return memoryRegion{}, fmt.Errorf("invalid inode: %v", err)
	}

	pathname := ""
	if len(fields) >= 6 {
		pathname = fields[5]
	}

	return memoryRegion{
		Start:    start,
		End:      end,
		Perms:    perms,
		Offset:   offset,
		Dev:      dev,
		Inode:    inode,
		Pathname: pathname,
	}, nil
}

// parseMapsContent parses the full content of /proc/<pid>/maps into regions.
func parseMapsContent(content string) []memoryRegion {
	var regions []memoryRegion
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		region, err := parseMapsLine(line)
		if err != nil {
			continue
		}
		regions = append(regions, region)
	}
	return regions
}

// filterDumpableRegions returns only regions suitable for memory dumping.
// Keeps: readable + private regions, excluding kernel-injected pseudo-regions.
// Skips: [vvar], [vdso], [vsyscall] — kernel virtual memory, not useful for cred extraction.
func filterDumpableRegions(regions []memoryRegion) []memoryRegion {
	var result []memoryRegion
	for _, r := range regions {
		if !r.IsReadable() {
			continue
		}
		if !r.IsPrivate() {
			continue
		}
		// Skip kernel virtual regions
		switch r.Pathname {
		case "[vvar]", "[vdso]", "[vsyscall]":
			continue
		}
		result = append(result, r)
	}
	return result
}

// maxDumpSize is the safety limit to prevent excessive memory consumption.
// 512 MB is generous enough for most processes including sshd/gnome-keyring.
const maxDumpSize = 512 * 1024 * 1024

// totalRegionSize sums the sizes of all regions.
func totalRegionSize(regions []memoryRegion) uint64 {
	var total uint64
	for _, r := range regions {
		total += r.Size()
	}
	return total
}

// sanitizeFileName replaces characters that are invalid in filenames.
func sanitizeFileName(name string) string {
	name = strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' || r == ' ' {
			return '_'
		}
		return r
	}, name)
	if len(name) > 32 {
		name = name[:32]
	}
	return name
}

// truncateString truncates a string to maxLen, adding "..." if truncated.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// credentialProcesses lists process names commonly holding credentials in memory.
var credentialProcesses = []string{
	"sshd",
	"ssh-agent",
	"gnome-keyring-d", // truncated in /proc/<pid>/comm
	"gpg-agent",
	"sudo",
	"su",
	"login",
	"passwd",
	"nginx",
	"apache2",
	"httpd",
	"mysqld",
	"postgres",
	"mongod",
	"redis-server",
	"vault",
	"secretd",
}
