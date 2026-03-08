//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

// HandlesCommand enumerates open file descriptors for a process via /proc.
type HandlesCommand struct{}

func (c *HandlesCommand) Name() string        { return "handles" }
func (c *HandlesCommand) Description() string { return "Enumerate open file descriptors for a process (T1057)" }

func (c *HandlesCommand) Execute(task structs.Task) structs.CommandResult {
	var args handlesArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Error parsing parameters: %v", err)
		}
	}

	// pid 0 means "self" — resolve to current process
	if args.PID == 0 {
		args.PID = os.Getpid()
	}
	if args.PID < 0 {
		return errorResult("Error: pid is required")
	}

	if args.MaxCount <= 0 {
		args.MaxCount = 500
	}

	handles, err := enumerateLinuxFDs(args.PID, args.MaxCount)
	if err != nil {
		return errorf("Error enumerating file descriptors: %v", err)
	}

	// Apply type filter and build summary
	var filtered []handleInfo
	typeCounts := make(map[string]int)
	for _, h := range handles {
		if args.TypeName != "" && !strings.EqualFold(h.TypeName, args.TypeName) {
			continue
		}
		typeCounts[h.TypeName]++
		filtered = append(filtered, h)
	}

	return formatHandleResult(filtered, typeCounts, args, len(handles))
}

func enumerateLinuxFDs(pid, maxCount int) ([]handleInfo, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", fdDir, err)
	}

	var handles []handleInfo
	for i, entry := range entries {
		if i >= maxCount {
			break
		}

		fdNum, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdPath := filepath.Join(fdDir, entry.Name())
		target, err := os.Readlink(fdPath)
		if err != nil {
			// FD may have closed between ReadDir and Readlink
			continue
		}

		h := handleInfo{
			Handle:   fdNum,
			TypeName: classifyFDTarget(target),
			Name:     target,
		}
		handles = append(handles, h)
	}

	sort.Slice(handles, func(i, j int) bool { return handles[i].Handle < handles[j].Handle })
	return handles, nil
}

// classifyFDTarget determines the type of a file descriptor from its readlink target.
func classifyFDTarget(target string) string {
	switch {
	case strings.HasPrefix(target, "socket:"):
		return "socket"
	case strings.HasPrefix(target, "pipe:"):
		return "pipe"
	case strings.HasPrefix(target, "anon_inode:"):
		inner := strings.TrimPrefix(target, "anon_inode:")
		inner = strings.Trim(inner, "[]")
		if inner != "" {
			return inner
		}
		return "anon_inode"
	case target == "/dev/null" || target == "/dev/zero" || target == "/dev/urandom" || target == "/dev/random":
		return "device"
	case strings.HasPrefix(target, "/dev/pts/") || strings.HasPrefix(target, "/dev/tty"):
		return "tty"
	case strings.HasPrefix(target, "/dev/"):
		return "device"
	default:
		return "file"
	}
}
