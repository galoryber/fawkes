//go:build darwin

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"
)

func scanProcessMemory(pid int, searchBytes []byte, maxResults int, contextBytes int) ([]memScanMatch, int, uint64, error) {
	if pid != os.Getpid() {
		return nil, 0, 0, fmt.Errorf("remote process scanning requires task_for_pid entitlement (root + SIP disabled); use pid 0 for self-scan")
	}

	regions, err := parseDarwinRegions(pid)
	if err != nil {
		return nil, 0, 0, err
	}

	var matches []memScanMatch
	var regionsScanned int
	var bytesScanned uint64

	for _, region := range regions {
		if len(matches) >= maxResults {
			break
		}

		if !region.Readable {
			continue
		}

		regionSize := region.End - region.Start
		if regionSize > 256*1024*1024 {
			continue
		}

		regionsScanned++

		//nolint:gosec // intentional memory read for red team tool
		data := unsafe.Slice((*byte)(unsafe.Pointer(region.Start)), regionSize)

		safeBuf := make([]byte, regionSize)
		copied := safeMemCopy(safeBuf, data)
		if copied == 0 {
			continue
		}

		bytesScanned += uint64(copied)
		matches = searchInRegion(safeBuf[:copied], uint64(region.Start), searchBytes, contextBytes, maxResults, matches)
	}

	return matches, regionsScanned, bytesScanned, nil
}

type darwinRegion struct {
	Start    uintptr
	End      uintptr
	Readable bool
}

func parseDarwinRegions(pid int) ([]darwinRegion, error) {
	out, err := exec.Command("vmmap", "--wide", strconv.Itoa(pid)).CombinedOutput()
	if err != nil {
		return parseDarwinRegionsFallback(pid)
	}

	var regions []darwinRegion
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] == '=' || line[0] == '-' {
			continue
		}

		dashIdx := strings.Index(line, "-")
		if dashIdx < 0 {
			continue
		}

		prefix := strings.TrimSpace(line[:dashIdx])
		if len(prefix) == 0 {
			continue
		}

		var start, end uint64
		if _, err := fmt.Sscanf(prefix, "%x", &start); err != nil {
			continue
		}

		rest := line[dashIdx+1:]
		spaceIdx := strings.IndexAny(rest, " \t")
		if spaceIdx < 0 {
			continue
		}
		endStr := strings.TrimSpace(rest[:spaceIdx])
		if _, err := fmt.Sscanf(endStr, "%x", &end); err != nil {
			continue
		}

		readable := strings.Contains(rest, "r-") || strings.Contains(rest, "rw") || strings.Contains(rest, "rx")
		if start > 0 && end > start {
			regions = append(regions, darwinRegion{
				Start:    uintptr(start),
				End:      uintptr(end),
				Readable: readable,
			})
		}
	}

	if len(regions) == 0 {
		return parseDarwinRegionsFallback(pid)
	}
	return regions, nil
}

func parseDarwinRegionsFallback(_ int) ([]darwinRegion, error) {
	return nil, fmt.Errorf("cannot enumerate memory regions (vmmap not available)")
}

func safeMemCopy(dst []byte, src []byte) int {
	defer func() { recover() }() //nolint:errcheck // intentional panic recovery for memory reads
	copy(dst, src)
	return len(dst)
}
