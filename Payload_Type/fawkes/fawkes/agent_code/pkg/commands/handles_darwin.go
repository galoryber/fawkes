//go:build darwin

package commands

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

// HandlesCommand enumerates open file descriptors for a process via lsof.
type HandlesCommand struct{}

func (c *HandlesCommand) Name() string { return "handles" }
func (c *HandlesCommand) Description() string {
	return "Enumerate open file descriptors for a process (T1057)"
}

func (c *HandlesCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[handlesArgs](task)
	if parseErr != nil {
		return *parseErr
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

	handles, err := enumerateDarwinFDs(args.PID, args.MaxCount)
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

// enumerateDarwinFDs uses lsof to enumerate open file descriptors.
func enumerateDarwinFDs(pid, maxCount int) ([]handleInfo, error) {
	out, err := execCmdTimeoutOutput("lsof", "-p", strconv.Itoa(pid), "-F", "ftn")
	if err != nil {
		return nil, fmt.Errorf("lsof failed: %w", err)
	}

	return parseLsofOutput(string(out), maxCount), nil
}

// parseLsofOutput parses lsof -F ftn output.
// Each line starts with a field identifier: p=PID, f=fd, t=type, n=name.
func parseLsofOutput(output string, maxCount int) []handleInfo {
	var handles []handleInfo
	var current handleInfo
	inFD := false

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}

		field := line[0]
		value := line[1:]

		switch field {
		case 'p':
			continue
		case 'f':
			if inFD {
				handles = append(handles, current)
				if len(handles) >= maxCount {
					return handles
				}
			}
			current = handleInfo{}
			inFD = true
			fd, err := strconv.Atoi(value)
			if err != nil {
				// Non-numeric fds like "cwd", "txt", "mem", "rtd"
				current.Handle = -1
				current.TypeName = value
				continue
			}
			current.Handle = fd
		case 't':
			if inFD {
				current.TypeName = mapLsofType(value)
			}
		case 'n':
			if inFD {
				current.Name = value
			}
		}
	}

	if inFD {
		handles = append(handles, current)
	}

	return handles
}

// mapLsofType converts lsof type codes to human-readable names.
func mapLsofType(t string) string {
	switch t {
	case "REG":
		return "file"
	case "DIR":
		return "directory"
	case "CHR":
		return "device"
	case "PIPE", "FIFO":
		return "pipe"
	case "unix":
		return "socket"
	case "IPv4", "IPv6":
		return "socket"
	case "KQUEUE":
		return "kqueue"
	case "systm":
		return "system"
	case "PSXSHM":
		return "shared_memory"
	default:
		if t == "" {
			return "unknown"
		}
		return strings.ToLower(t)
	}
}
