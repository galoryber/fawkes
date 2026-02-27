package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"fawkes/pkg/structs"
)

// TrCommand translates or deletes characters in a file (like Unix tr)
type TrCommand struct{}

func (c *TrCommand) Name() string        { return "tr" }
func (c *TrCommand) Description() string { return "Translate, squeeze, or delete characters in file content" }

type trArgs struct {
	Path    string `json:"path"`
	From    string `json:"from"`    // characters to translate from
	To      string `json:"to"`      // characters to translate to
	Delete  string `json:"delete"`  // characters to delete
	Squeeze bool   `json:"squeeze"` // squeeze repeated characters
}

// expandTrClass expands character class notations like [:upper:], [:lower:], [:digit:]
func expandTrClass(s string) string {
	s = strings.ReplaceAll(s, "[:upper:]", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	s = strings.ReplaceAll(s, "[:lower:]", "abcdefghijklmnopqrstuvwxyz")
	s = strings.ReplaceAll(s, "[:digit:]", "0123456789")
	s = strings.ReplaceAll(s, "[:alpha:]", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
	s = strings.ReplaceAll(s, "[:alnum:]", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	s = strings.ReplaceAll(s, "[:space:]", " \t\n\r\f\v")
	s = strings.ReplaceAll(s, "[:punct:]", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")

	// Expand ranges like a-z, A-Z, 0-9
	var result []rune
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		if i+2 < len(runes) && runes[i+1] == '-' {
			start, end := runes[i], runes[i+2]
			if start <= end {
				for c := start; c <= end; c++ {
					result = append(result, c)
				}
			}
			i += 2
		} else {
			result = append(result, runes[i])
		}
	}
	return string(result)
}

func (c *TrCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{Output: "Error: no parameters provided", Status: "error", Completed: true}
	}

	var args trArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error parsing parameters: %v", err), Status: "error", Completed: true}
	}
	if args.Path == "" {
		return structs.CommandResult{Output: "Error: path is required", Status: "error", Completed: true}
	}
	if args.From == "" && args.Delete == "" && !args.Squeeze {
		return structs.CommandResult{Output: "Error: from/to, delete, or squeeze is required", Status: "error", Completed: true}
	}

	lines, err := readLines(args.Path)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error: %v", err), Status: "error", Completed: true}
	}

	content := strings.Join(lines, "\n")

	// Build translation map
	if args.Delete != "" {
		deleteSet := expandTrClass(args.Delete)
		delRunes := make(map[rune]bool)
		for _, r := range deleteSet {
			delRunes[r] = true
		}
		var result []rune
		for _, r := range content {
			if !delRunes[r] {
				result = append(result, r)
			}
		}
		content = string(result)
	}

	if args.From != "" {
		fromStr := expandTrClass(args.From)
		toStr := expandTrClass(args.To)
		fromRunes := []rune(fromStr)
		toRunes := []rune(toStr)

		// Pad 'to' to match 'from' length by repeating last char
		if len(toRunes) > 0 && len(toRunes) < len(fromRunes) {
			last := toRunes[len(toRunes)-1]
			for len(toRunes) < len(fromRunes) {
				toRunes = append(toRunes, last)
			}
		}

		trMap := make(map[rune]rune)
		for i, f := range fromRunes {
			if i < len(toRunes) {
				trMap[f] = toRunes[i]
			}
		}

		var result []rune
		for _, r := range content {
			if replacement, ok := trMap[r]; ok {
				result = append(result, replacement)
			} else {
				result = append(result, r)
			}
		}
		content = string(result)
	}

	if args.Squeeze {
		var result []rune
		var prev rune
		first := true
		for _, r := range content {
			if first || r != prev || !unicode.IsPrint(r) {
				result = append(result, r)
				prev = r
				first = false
			}
		}
		content = string(result)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] %d lines processed\n\n", len(lines)))
	sb.WriteString(content)
	if !strings.HasSuffix(content, "\n") {
		sb.WriteString("\n")
	}

	out := sb.String()
	if len(out) > 100000 {
		out = out[:100000] + "\n... (truncated)"
	}

	return structs.CommandResult{Output: out, Status: "success", Completed: true}
}
