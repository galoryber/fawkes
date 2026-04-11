//go:build !windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// masqueradeHide hides a file or directory from standard enumeration.
// Linux: dot-prefix rename + immutable attribute (if root).
// macOS: UF_HIDDEN flag + .hidden file entry.
func masqueradeHide(path string) structs.CommandResult {
	info, err := os.Stat(path)
	if err != nil {
		return errorf("Error: path not found: %v", err)
	}

	var actions []string

	// Dot-prefix: rename to hidden name if not already
	base := filepath.Base(path)
	if !strings.HasPrefix(base, ".") {
		newPath := filepath.Join(filepath.Dir(path), "."+base)
		if err := os.Rename(path, newPath); err != nil {
			return errorf("Error renaming to hidden: %v", err)
		}
		actions = append(actions, fmt.Sprintf("Renamed: %s → %s", path, newPath))
		path = newPath
	} else {
		actions = append(actions, fmt.Sprintf("Already hidden (dot-prefix): %s", path))
	}

	// chflags hidden on macOS (UF_HIDDEN = 0x8000)
	if err := setHiddenFlag(path, true); err == nil {
		actions = append(actions, "Set OS hidden flag")
	}

	typeStr := "file"
	if info.IsDir() {
		typeStr = "directory"
	}

	return successf("[+] Hidden %s: %s\n%s", typeStr, path, strings.Join(actions, "\n"))
}

// masqueradeUnhide reverses hiding operations.
func masqueradeUnhide(path string) structs.CommandResult {
	_, err := os.Stat(path)
	if err != nil {
		return errorf("Error: path not found: %v", err)
	}

	var actions []string

	// Remove hidden flag
	if err := setHiddenFlag(path, false); err == nil {
		actions = append(actions, "Cleared OS hidden flag")
	}

	// Remove dot-prefix if present
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") && len(base) > 1 {
		newPath := filepath.Join(filepath.Dir(path), base[1:])
		if err := os.Rename(path, newPath); err != nil {
			return errorf("Error renaming to visible: %v", err)
		}
		actions = append(actions, fmt.Sprintf("Renamed: %s → %s", path, newPath))
		path = newPath
	}

	return successf("[+] Unhidden: %s\n%s", path, strings.Join(actions, "\n"))
}
