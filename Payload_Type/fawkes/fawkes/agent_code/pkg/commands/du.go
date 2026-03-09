package commands

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"fawkes/pkg/structs"
)

// DuCommand implements disk usage reporting
type DuCommand struct{}

func (c *DuCommand) Name() string {
	return "du"
}

func (c *DuCommand) Description() string {
	return "Report disk usage for files and directories"
}

type duArgs struct {
	Path     string `json:"path"`
	MaxDepth int    `json:"max_depth"` // 0 = summary only, -1 = unlimited (default 1)
}

type duEntry struct {
	path  string
	size  int64
	isDir bool
}

func (c *DuCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: no parameters provided")
	}

	var args duArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		args.Path = strings.TrimSpace(task.Params)
	}

	if args.Path == "" {
		return errorResult("Error: path is required")
	}

	// Default max_depth = 1 (show immediate children)
	if args.MaxDepth == 0 {
		args.MaxDepth = 1
	}

	info, err := os.Stat(args.Path)
	if err != nil {
		return errorf("Error: %v", err)
	}

	if !info.IsDir() {
		return successf("[*] %s\n  Size: %s (%d bytes)", args.Path, formatFileSize(info.Size()), info.Size())
	}

	// Walk directory and collect sizes
	dirSizes := make(map[string]int64)
	var totalSize int64
	var fileCount int

	basePath := filepath.Clean(args.Path)
	baseDepth := strings.Count(basePath, string(filepath.Separator))

	_ = filepath.WalkDir(basePath, func(path string, d fs.DirEntry, err error) error {
		if task.DidStop() {
			return fmt.Errorf("cancelled")
		}
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			info, infoErr := d.Info()
			if infoErr != nil {
				return nil
			}
			totalSize += info.Size()
			fileCount++

			// Accumulate into parent directories
			dir := filepath.Dir(path)
			for {
				dirSizes[dir] += info.Size()
				parent := filepath.Dir(dir)
				if parent == dir {
					break
				}
				dir = parent
			}
		}
		return nil
	})

	// Collect entries to display based on max_depth
	var entries []duEntry
	for dir, size := range dirSizes {
		dirDepth := strings.Count(filepath.Clean(dir), string(filepath.Separator))
		relDepth := dirDepth - baseDepth
		if args.MaxDepth > 0 && relDepth > args.MaxDepth {
			continue
		}
		if relDepth < 0 {
			continue
		}
		entries = append(entries, duEntry{path: dir, size: size, isDir: true})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].size > entries[j].size
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] %s — %s total, %d files\n\n", basePath, formatFileSize(totalSize), fileCount))
	sb.WriteString(fmt.Sprintf("  %10s  %s\n", "Size", "Path"))
	sb.WriteString(fmt.Sprintf("  %10s  %s\n", "----", "----"))

	for _, e := range entries {
		sb.WriteString(fmt.Sprintf("  %10s  %s\n", formatFileSize(e.size), e.path))
	}

	return successResult(sb.String())
}
