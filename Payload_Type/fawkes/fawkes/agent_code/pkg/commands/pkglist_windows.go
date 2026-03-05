//go:build windows

package commands

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// pkgListWindowsNative enumerates installed software by reading the Windows
// registry directly — no PowerShell subprocess spawned.
// Reads from both Uninstall keys (64-bit and 32-bit/WOW6432Node).
func pkgListWindowsNative() string {
	type installedPkg struct {
		name    string
		version string
	}

	uninstallPaths := []string{
		`Software\Microsoft\Windows\CurrentVersion\Uninstall`,
		`Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}

	seen := make(map[string]bool)
	var pkgs []installedPkg

	for _, path := range uninstallPaths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
		if err != nil {
			continue
		}

		subkeys, err := key.ReadSubKeyNames(-1)
		key.Close()
		if err != nil {
			continue
		}

		for _, subkeyName := range subkeys {
			subkey, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+subkeyName, registry.READ)
			if err != nil {
				continue
			}

			displayName, _, err := subkey.GetStringValue("DisplayName")
			subkey.Close()
			if err != nil || displayName == "" {
				continue
			}

			// Deduplicate (WOW6432Node may contain same entries)
			if seen[displayName] {
				continue
			}
			seen[displayName] = true

			// Re-open to get version (separate call to handle missing values)
			subkey, err = registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+subkeyName, registry.READ)
			if err != nil {
				pkgs = append(pkgs, installedPkg{name: displayName})
				continue
			}
			version, _, _ := subkey.GetStringValue("DisplayVersion")
			subkey.Close()

			pkgs = append(pkgs, installedPkg{name: displayName, version: version})
		}
	}

	if len(pkgs) == 0 {
		return ""
	}

	// Sort by name
	sort.Slice(pkgs, func(i, j int) bool {
		return strings.ToLower(pkgs[i].name) < strings.ToLower(pkgs[j].name)
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  Installed programs: %d\n\n", len(pkgs)))
	sb.WriteString(fmt.Sprintf("  %-55s %s\n", "Name", "Version"))
	sb.WriteString("  " + strings.Repeat("-", 70) + "\n")
	for i, pkg := range pkgs {
		sb.WriteString(fmt.Sprintf("  %-55s %s\n", pkg.name, pkg.version))
		if i >= 199 {
			sb.WriteString(fmt.Sprintf("  ... and %d more (showing first 200)\n", len(pkgs)-200))
			break
		}
	}
	return sb.String()
}
