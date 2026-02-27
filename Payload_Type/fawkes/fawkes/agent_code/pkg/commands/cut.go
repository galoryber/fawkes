package commands

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

// CutCommand extracts fields from text files (like Unix cut)
type CutCommand struct{}

func (c *CutCommand) Name() string        { return "cut" }
func (c *CutCommand) Description() string { return "Extract fields or character ranges from file lines" }

type cutArgs struct {
	Path      string `json:"path"`
	Delimiter string `json:"delimiter"`
	Fields    string `json:"fields"`    // e.g. "1,3" or "1-3" or "2-"
	Chars     string `json:"chars"`     // character positions, e.g. "1-10"
}

// parseRanges parses range specs like "1,3", "1-3", "2-" into a set of 1-based indices
func parseRanges(spec string, maxVal int) []int {
	var result []int
	seen := make(map[int]bool)

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, end := 1, maxVal
			if bounds[0] != "" {
				if v, err := strconv.Atoi(bounds[0]); err == nil {
					start = v
				}
			}
			if bounds[1] != "" {
				if v, err := strconv.Atoi(bounds[1]); err == nil {
					end = v
				}
			}
			if start < 1 {
				start = 1
			}
			if end > maxVal {
				end = maxVal
			}
			for i := start; i <= end; i++ {
				if !seen[i] {
					seen[i] = true
					result = append(result, i)
				}
			}
		} else {
			if v, err := strconv.Atoi(part); err == nil && v >= 1 && v <= maxVal {
				if !seen[v] {
					seen[v] = true
					result = append(result, v)
				}
			}
		}
	}
	return result
}

func (c *CutCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{Output: "Error: no parameters provided", Status: "error", Completed: true}
	}

	var args cutArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error parsing parameters: %v", err), Status: "error", Completed: true}
	}
	if args.Path == "" {
		return structs.CommandResult{Output: "Error: path is required", Status: "error", Completed: true}
	}
	if args.Fields == "" && args.Chars == "" {
		return structs.CommandResult{Output: "Error: fields or chars is required", Status: "error", Completed: true}
	}

	lines, err := readLines(args.Path)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error: %v", err), Status: "error", Completed: true}
	}

	delim := args.Delimiter
	if delim == "" {
		delim = "\t"
	}

	var sb strings.Builder
	mode := "fields"
	if args.Chars != "" {
		mode = "chars"
	}
	sb.WriteString(fmt.Sprintf("[*] %d lines, mode: %s\n\n", len(lines), mode))

	for _, line := range lines {
		if args.Chars != "" {
			// Character mode
			runes := []rune(line)
			indices := parseRanges(args.Chars, len(runes))
			var chars []rune
			for _, idx := range indices {
				chars = append(chars, runes[idx-1])
			}
			sb.WriteString(string(chars))
		} else {
			// Field mode
			fields := strings.Split(line, delim)
			indices := parseRanges(args.Fields, len(fields))
			var selected []string
			for _, idx := range indices {
				selected = append(selected, fields[idx-1])
			}
			sb.WriteString(strings.Join(selected, delim))
		}
		sb.WriteString("\n")
	}

	out := sb.String()
	if len(out) > 100000 {
		out = out[:100000] + "\n... (truncated)"
	}

	return structs.CommandResult{Output: out, Status: "success", Completed: true}
}
