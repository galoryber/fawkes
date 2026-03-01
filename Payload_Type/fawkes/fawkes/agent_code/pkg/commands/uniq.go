package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"fawkes/pkg/structs"
)

// UniqCommand implements line deduplication
type UniqCommand struct{}

func (c *UniqCommand) Name() string {
	return "uniq"
}

func (c *UniqCommand) Description() string {
	return "Filter or count duplicate lines in a file"
}

type uniqArgs struct {
	Path      string `json:"path"`
	Count     bool   `json:"count"`       // prefix lines with occurrence count
	Duplicate bool   `json:"duplicate"`   // only show duplicate lines
	Unique    bool   `json:"unique_only"` // only show unique lines (appear once)
}

func (c *UniqCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: no parameters provided",
			Status:    "error",
			Completed: true,
		}
	}

	var args uniqArgs
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

	// Count consecutive duplicates (like Unix uniq)
	type lineCount struct {
		line  string
		count int
	}

	var groups []lineCount
	for _, line := range lines {
		if len(groups) > 0 && groups[len(groups)-1].line == line {
			groups[len(groups)-1].count++
		} else {
			groups = append(groups, lineCount{line, 1})
		}
	}

	// Sort by count descending if showing counts
	if args.Count {
		sort.SliceStable(groups, func(i, j int) bool {
			return groups[i].count > groups[j].count
		})
	}

	maxOutput := 100000
	var sb strings.Builder

	totalLines := len(lines)
	uniqueCount := 0
	for _, g := range groups {
		if g.count == 1 {
			uniqueCount++
		}
	}
	sb.WriteString(fmt.Sprintf("[*] %d lines, %d groups, %d unique\n\n", totalLines, len(groups), uniqueCount))

	outputCount := 0
	for _, g := range groups {
		if args.Duplicate && g.count < 2 {
			continue
		}
		if args.Unique && g.count != 1 {
			continue
		}

		if sb.Len() > maxOutput {
			sb.WriteString("\n... output truncated ...\n")
			break
		}

		if args.Count {
			sb.WriteString(fmt.Sprintf("%7d %s\n", g.count, g.line))
		} else {
			sb.WriteString(g.line)
			sb.WriteString("\n")
		}
		outputCount++
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}
