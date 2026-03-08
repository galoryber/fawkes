//go:build !windows

package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"fawkes/pkg/structs"
)

type NamedPipesCommand struct{}

func (c *NamedPipesCommand) Name() string {
	return "named-pipes"
}

func (c *NamedPipesCommand) Description() string {
	return "List Unix domain sockets and named pipes (FIFOs)"
}

func (c *NamedPipesCommand) Execute(task structs.Task) structs.CommandResult {
	var args namedPipesArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Failed to parse parameters: %v", err)
		}
	}

	var sb strings.Builder

	// Unix domain sockets
	sockets, err := enumerateUnixSockets()
	if err != nil {
		sb.WriteString(fmt.Sprintf("Unix sockets: error — %v\n", err))
	} else {
		if args.Filter != "" {
			sockets = filterEntries(sockets, args.Filter)
		}
		sort.Strings(sockets)
		sb.WriteString(fmt.Sprintf("Unix domain sockets: %d\n", len(sockets)))
		if args.Filter != "" {
			sb.WriteString(fmt.Sprintf("Filter: %s\n", args.Filter))
		}
		sb.WriteString("\n")
		for _, s := range sockets {
			sb.WriteString(fmt.Sprintf("  %s\n", s))
		}
	}

	// Named pipes (FIFOs) in common locations
	fifos := enumerateFIFOs()
	if len(fifos) > 0 {
		if args.Filter != "" {
			fifos = filterEntries(fifos, args.Filter)
		}
		sort.Strings(fifos)
		sb.WriteString(fmt.Sprintf("\nNamed pipes (FIFOs): %d\n\n", len(fifos)))
		for _, f := range fifos {
			sb.WriteString(fmt.Sprintf("  %s\n", f))
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// enumerateUnixSockets reads active Unix domain sockets from /proc/net/unix (Linux)
// or falls back to scanning common socket directories (macOS).
func enumerateUnixSockets() ([]string, error) {
	if runtime.GOOS == "linux" {
		return enumerateUnixSocketsLinux()
	}
	return enumerateUnixSocketsScan()
}

// enumerateUnixSocketsLinux parses /proc/net/unix for socket paths.
func enumerateUnixSocketsLinux() ([]string, error) {
	f, err := os.Open("/proc/net/unix")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line

	for scanner.Scan() {
		line := scanner.Text()
		// Format: Num RefCount Protocol Flags Type St Inode [Path]
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		path := fields[len(fields)-1]
		// Skip abstract sockets (start with @) unless they have a readable name
		if path == "" {
			continue
		}
		if !seen[path] {
			seen[path] = true
		}
	}

	var result []string
	for path := range seen {
		result = append(result, path)
	}
	return result, scanner.Err()
}

// enumerateUnixSocketsScan scans common directories for socket files (macOS fallback).
func enumerateUnixSocketsScan() ([]string, error) {
	dirs := []string{
		"/var/run",
		"/tmp",
		"/var/tmp",
		"/private/var/run",
		"/private/tmp",
	}

	var sockets []string
	seen := make(map[string]bool)

	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.Type()&os.ModeSocket != 0 {
				if !seen[path] {
					seen[path] = true
					sockets = append(sockets, path)
				}
			}
			return nil
		})
	}

	return sockets, nil
}

// enumerateFIFOs scans common directories for FIFO (named pipe) files.
func enumerateFIFOs() []string {
	dirs := []string{"/tmp", "/var/tmp", "/var/run", "/run"}
	if runtime.GOOS == "darwin" {
		dirs = append(dirs, "/private/tmp", "/private/var/run")
	}

	var fifos []string
	seen := make(map[string]bool)

	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.Type()&os.ModeNamedPipe != 0 {
				if !seen[path] {
					seen[path] = true
					fifos = append(fifos, path)
				}
			}
			return nil
		})
	}

	return fifos
}

// filterEntries returns only entries containing the filter string (case-insensitive).
func filterEntries(entries []string, filter string) []string {
	filterLower := strings.ToLower(filter)
	var result []string
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e), filterLower) {
			result = append(result, e)
		}
	}
	return result
}
