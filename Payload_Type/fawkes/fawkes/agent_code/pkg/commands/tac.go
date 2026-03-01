package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// TacCommand reverses lines in a file (like Unix tac)
type TacCommand struct{}

func (c *TacCommand) Name() string        { return "tac" }
func (c *TacCommand) Description() string { return "Print file lines in reverse order" }

type tacArgs struct {
	Path string `json:"path"`
}

func (c *TacCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{Output: "Error: no parameters provided", Status: "error", Completed: true}
	}

	var args tacArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		args.Path = strings.TrimSpace(task.Params)
	}
	if args.Path == "" {
		return structs.CommandResult{Output: "Error: path is required", Status: "error", Completed: true}
	}

	lines, err := readLines(args.Path)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error: %v", err), Status: "error", Completed: true}
	}

	// Reverse lines
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] %d lines (reversed)\n\n", len(lines)))
	for _, l := range lines {
		sb.WriteString(l)
		sb.WriteString("\n")
	}

	out := sb.String()
	if len(out) > 100000 {
		out = out[:100000] + "\n... (truncated)"
	}

	return structs.CommandResult{Output: out, Status: "success", Completed: true}
}
