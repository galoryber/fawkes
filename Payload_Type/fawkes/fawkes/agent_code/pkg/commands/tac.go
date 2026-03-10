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
		return errorResult("Error: no parameters provided")
	}

	var args tacArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		args.Path = strings.TrimSpace(task.Params)
	}
	if args.Path == "" {
		return errorResult("Error: path is required")
	}

	lines, err := readLines(args.Path)
	if err != nil {
		return errorf("Error: %v", err)
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

	return successResult(out)
}
