//go:build linux

package commands

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// memRegion represents a parsed /proc/pid/maps entry
type memRegion struct {
	Start uint64
	End   uint64
	Perms string
	Path  string
}

func scanProcessMemory(pid int, searchBytes []byte, maxResults int, contextBytes int) ([]memScanMatch, int, uint64, error) {
	// Parse /proc/pid/maps for readable regions
	regions, err := parseMemoryMaps(pid)
	if err != nil {
		return nil, 0, 0, err
	}

	// Open /proc/pid/mem for reading
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("open %s: %v (ptrace_scope may restrict access)", memPath, err)
	}
	defer func() { _ = memFile.Close() }()

	var matches []memScanMatch
	var regionsScanned int
	var bytesScanned uint64

	const maxChunkSize = 4 * 1024 * 1024 // 4 MB

	for _, region := range regions {
		if len(matches) >= maxResults {
			break
		}

		// Only scan readable regions
		if len(region.Perms) < 1 || region.Perms[0] != 'r' {
			continue
		}

		regionSize := region.End - region.Start

		// Skip very large regions (>256 MB)
		if regionSize > 256*1024*1024 {
			continue
		}

		regionsScanned++

		// Read in chunks
		var offset uint64
		for offset < regionSize && len(matches) < maxResults {
			chunkSize := regionSize - offset
			if chunkSize > maxChunkSize {
				chunkSize = maxChunkSize
			}

			buf := make([]byte, chunkSize)
			n, err := memFile.ReadAt(buf, int64(region.Start+offset))
			if err != nil && n == 0 {
				break // Can't read this region
			}

			bytesScanned += uint64(n)
			matches = searchInRegion(buf[:n], region.Start+offset, searchBytes, contextBytes, maxResults, matches)

			offset += chunkSize
		}
	}

	return matches, regionsScanned, bytesScanned, nil
}

// parseMemoryMaps reads /proc/pid/maps and returns readable regions
func parseMemoryMaps(pid int) ([]memRegion, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %v", mapsPath, err)
	}
	defer func() { _ = f.Close() }()

	var regions []memRegion
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: address perms offset dev inode pathname
		// e.g.: 00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/dbus-daemon
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		addrParts := strings.SplitN(fields[0], "-", 2)
		if len(addrParts) != 2 {
			continue
		}

		start, err := strconv.ParseUint(addrParts[0], 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(addrParts[1], 16, 64)
		if err != nil {
			continue
		}

		perms := fields[1]
		path := ""
		if len(fields) >= 6 {
			path = fields[5]
		}

		regions = append(regions, memRegion{
			Start: start,
			End:   end,
			Perms: perms,
			Path:  path,
		})
	}

	return regions, scanner.Err()
}
