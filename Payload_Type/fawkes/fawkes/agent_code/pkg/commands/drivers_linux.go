//go:build linux

package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func enumerateDrivers() ([]DriverInfo, error) {
	// Parse /proc/modules: name size refcount deps state address
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/modules: %v", err)
	}

	var drivers []DriverInfo
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		name := fields[0]
		size, _ := strconv.ParseUint(fields[1], 10, 64)

		status := "loaded"
		if len(fields) >= 5 {
			// State field: Live, Loading, Unloading
			status = strings.ToLower(fields[4])
		}

		// Deps field shows comma-separated dependent modules
		deps := ""
		if len(fields) >= 4 && fields[3] != "-" {
			deps = strings.TrimSuffix(fields[3], ",")
		}

		path := fmt.Sprintf("/lib/modules/.../kernel/.../%s.ko", name)
		// Try to find actual path via modinfo-style lookup
		modPath := findModulePath(name)
		if modPath != "" {
			path = modPath
		}

		d := DriverInfo{
			Name:   name,
			Size:   size,
			Status: status,
			Path:   path,
		}
		if deps != "" {
			d.Version = fmt.Sprintf("deps: %s", deps)
		}

		drivers = append(drivers, d)
	}

	return drivers, nil
}

// findModulePath tries to locate the .ko file for a module
func findModulePath(name string) string {
	// Check common paths under /sys/module/<name>
	sysPath := fmt.Sprintf("/sys/module/%s", name)
	if _, err := os.Stat(sysPath); err != nil {
		return ""
	}

	// Try to read the module's parameters or coresize as indication it's loaded
	// The actual .ko path isn't directly available without modinfo binary
	// Return empty to use the default placeholder
	return ""
}
