//go:build darwin

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func enumerateDrivers() ([]DriverInfo, error) {
	var drivers []DriverInfo

	// Parse /Library/Extensions and /System/Library/Extensions for kexts
	kextDirs := []string{
		"/Library/Extensions",
		"/System/Library/Extensions",
	}

	for _, dir := range kextDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".kext") {
				continue
			}

			name := strings.TrimSuffix(entry.Name(), ".kext")
			path := filepath.Join(dir, entry.Name())

			info, _ := entry.Info()
			var size uint64
			if info != nil {
				size = uint64(info.Size())
			}

			// Try to get version from Info.plist
			version := readKextVersion(path)

			drivers = append(drivers, DriverInfo{
				Name:    name,
				Path:    path,
				Size:    size,
				Status:  "installed",
				Version: version,
			})
		}
	}

	// Also check system extensions (macOS 10.15+)
	sysExtDir := "/Library/SystemExtensions"
	if entries, err := os.ReadDir(sysExtDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasSuffix(entry.Name(), ".systemextension") {
				name := strings.TrimSuffix(entry.Name(), ".systemextension")
				drivers = append(drivers, DriverInfo{
					Name:   name,
					Path:   filepath.Join(sysExtDir, entry.Name()),
					Status: "system-extension",
				})
			}
		}
	}

	if len(drivers) == 0 {
		return nil, fmt.Errorf("no kernel extensions found")
	}

	return drivers, nil
}

func readKextVersion(kextPath string) string {
	plistPath := filepath.Join(kextPath, "Contents", "Info.plist")
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return ""
	}

	// Simple XML parsing for CFBundleShortVersionString
	content := string(data)
	key := "CFBundleShortVersionString"
	idx := strings.Index(content, key)
	if idx < 0 {
		return ""
	}

	// Find the <string> tag after the key
	rest := content[idx+len(key):]
	startTag := "<string>"
	endTag := "</string>"
	start := strings.Index(rest, startTag)
	if start < 0 {
		return ""
	}
	rest = rest[start+len(startTag):]
	end := strings.Index(rest, endTag)
	if end < 0 {
		return ""
	}

	return rest[:end]
}
