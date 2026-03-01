package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

// SortCommand implements file line sorting
type SortCommand struct{}

func (c *SortCommand) Name() string {
	return "sort"
}

func (c *SortCommand) Description() string {
	return "Sort lines of a file"
}

type sortArgs struct {
	Path    string `json:"path"`
	Reverse bool   `json:"reverse"`
	Numeric bool   `json:"numeric"`
	Unique  bool   `json:"unique"`
}

func (c *SortCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: no parameters provided",
			Status:    "error",
			Completed: true,
		}
	}

	var args sortArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		args.Path = strings.TrimSpace(task.Params)
	}

	if args.Path == "" {
		return structs.CommandResult{
			Output:    "Error: path is required",
			Status:    "error",
			Completed: true,
		}
	}

	lines, err := readLines(args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading %s: %v", args.Path, err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Numeric {
		sort.SliceStable(lines, func(i, j int) bool {
			ni := extractNumber(lines[i])
			nj := extractNumber(lines[j])
			if args.Reverse {
				return ni > nj
			}
			return ni < nj
		})
	} else {
		sort.SliceStable(lines, func(i, j int) bool {
			if args.Reverse {
				return strings.ToLower(lines[i]) > strings.ToLower(lines[j])
			}
			return strings.ToLower(lines[i]) < strings.ToLower(lines[j])
		})
	}

	if args.Unique {
		lines = uniqueLines(lines)
	}

	// Limit output
	maxOutput := 100000
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] %d lines", len(lines)))
	if args.Reverse {
		sb.WriteString(" (reversed)")
	}
	if args.Numeric {
		sb.WriteString(" (numeric)")
	}
	if args.Unique {
		sb.WriteString(" (unique)")
	}
	sb.WriteString("\n\n")

	for _, line := range lines {
		if sb.Len() > maxOutput {
			sb.WriteString("\n... output truncated ...\n")
			break
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func extractNumber(s string) float64 {
	s = strings.TrimSpace(s)
	// Try to parse the leading number from the line
	numStr := ""
	for _, c := range s {
		if (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+' {
			numStr += string(c)
		} else if numStr != "" {
			break
		}
	}
	if numStr == "" {
		return 0
	}
	n, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0
	}
	return n
}

func uniqueLines(lines []string) []string {
	if len(lines) == 0 {
		return lines
	}
	result := []string{lines[0]}
	for i := 1; i < len(lines); i++ {
		if lines[i] != lines[i-1] {
			result = append(result, lines[i])
		}
	}
	return result
}
