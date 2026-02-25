//go:build linux

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func listProcessModules(pid int) ([]ModuleInfo, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %v", mapsPath, err)
	}

	// Track first/last address per path for size calculation
	type addrRange struct {
		firstStart uint64
		lastEnd    uint64
		path       string
	}
	regionMap := make(map[string]*addrRange)
	// Maintain insertion order
	var order []string

	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := fields[len(fields)-1]
		if !strings.HasPrefix(path, "/") {
			continue // Skip [heap], [stack], [vdso], anon mappings
		}

		// Parse address range
		addrParts := strings.SplitN(fields[0], "-", 2)
		if len(addrParts) != 2 {
			continue
		}
		startAddr, err := strconv.ParseUint(addrParts[0], 16, 64)
		if err != nil {
			continue
		}
		endAddr, err := strconv.ParseUint(addrParts[1], 16, 64)
		if err != nil {
			continue
		}

		if existing, ok := regionMap[path]; ok {
			if startAddr < existing.firstStart {
				existing.firstStart = startAddr
			}
			if endAddr > existing.lastEnd {
				existing.lastEnd = endAddr
			}
		} else {
			regionMap[path] = &addrRange{
				firstStart: startAddr,
				lastEnd:    endAddr,
				path:       path,
			}
			order = append(order, path)
		}
	}

	var modules []ModuleInfo
	for _, path := range order {
		region := regionMap[path]
		modules = append(modules, ModuleInfo{
			Name:     filepath.Base(region.path),
			Path:     region.path,
			BaseAddr: fmt.Sprintf("0x%X", region.firstStart),
			Size:     region.lastEnd - region.firstStart,
		})
	}

	return modules, nil
}
