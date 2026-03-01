package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type StatCommand struct{}

func (c *StatCommand) Name() string { return "stat" }
func (c *StatCommand) Description() string {
	return "Display detailed file or directory metadata (T1083)"
}

type statArgs struct {
	Path string `json:"path"` // file or directory path
}

func (c *StatCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -path <file>",
			Status:    "error",
			Completed: true,
		}
	}

	var args statArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		args.Path = strings.TrimSpace(task.Params)
	}

	if args.Path == "" {
		return structs.CommandResult{
			Output:    "Error: path parameter is required",
			Status:    "error",
			Completed: true,
		}
	}

	// Resolve path
	path := args.Path
	if strings.HasPrefix(path, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, path[1:])
		}
	}

	info, err := os.Lstat(path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Build output
	var sb strings.Builder

	// Resolve absolute path
	absPath, _ := filepath.Abs(path)
	if absPath == "" {
		absPath = path
	}

	sb.WriteString(fmt.Sprintf("  File: %s\n", absPath))

	// File type
	fileType := statFileType(info)
	sb.WriteString(fmt.Sprintf("  Type: %s\n", fileType))

	// Size
	sb.WriteString(fmt.Sprintf("  Size: %d bytes (%s)\n", info.Size(), statFormatSize(info.Size())))

	// Permissions
	sb.WriteString(fmt.Sprintf("  Mode: %s (%04o)\n", info.Mode().String(), info.Mode().Perm()))

	// Platform-specific metadata (owner, inode, etc.)
	statPlatformInfo(&sb, info, path)

	// Timestamps
	sb.WriteString(fmt.Sprintf("Modify: %s\n", info.ModTime().Format(time.RFC3339)))

	// Symlink target
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err == nil {
			sb.WriteString(fmt.Sprintf("  Link: %s\n", target))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func statFileType(info os.FileInfo) string {
	mode := info.Mode()
	switch {
	case mode.IsRegular():
		return "regular file"
	case mode.IsDir():
		return "directory"
	case mode&os.ModeSymlink != 0:
		return "symbolic link"
	case mode&os.ModeNamedPipe != 0:
		return "named pipe (FIFO)"
	case mode&os.ModeSocket != 0:
		return "socket"
	case mode&os.ModeDevice != 0:
		if mode&os.ModeCharDevice != 0 {
			return "character device"
		}
		return "block device"
	default:
		return "unknown"
	}
}

func statFormatSize(bytes int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
		tb = gb * 1024
	)
	switch {
	case bytes >= tb:
		return fmt.Sprintf("%.1f TB", float64(bytes)/float64(tb))
	case bytes >= gb:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
