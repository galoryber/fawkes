package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"fawkes/pkg/structs"
)

// WcCommand implements word/line/byte counting
type WcCommand struct{}

func (c *WcCommand) Name() string {
	return "wc"
}

func (c *WcCommand) Description() string {
	return "Count lines, words, characters, and bytes in files"
}

type wcArgs struct {
	Path    string `json:"path"`
	Pattern string `json:"pattern"` // glob pattern for directory mode
}

type wcResult struct {
	path  string
	lines int
	words int
	chars int
	bytes int64
}

func (c *WcCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: no parameters provided",
			Status:    "error",
			Completed: true,
		}
	}

	var args wcArgs
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

	info, err := os.Stat(args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if info.IsDir() {
		return wcDirectory(args.Path, args.Pattern)
	}

	result, err := wcFile(args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    formatWcResult(result),
		Status:    "success",
		Completed: true,
	}
}

func wcFile(path string) (wcResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return wcResult{}, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return wcResult{}, err
	}

	r := wcResult{
		path:  path,
		bytes: info.Size(),
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		r.lines++
		line := scanner.Text()
		r.chars += utf8.RuneCountInString(line) + 1 // +1 for newline
		r.words += countWords(line)
	}

	return r, scanner.Err()
}

func countWords(s string) int {
	count := 0
	inWord := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			inWord = false
		} else if !inWord {
			inWord = true
			count++
		}
	}
	return count
}

func wcDirectory(dirPath, pattern string) structs.CommandResult {
	if pattern == "" {
		pattern = "*"
	}

	var results []wcResult
	var total wcResult
	total.path = "total"

	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if pattern != "*" {
			matched, _ := filepath.Match(pattern, filepath.Base(path))
			if !matched {
				return nil
			}
		}
		r, err := wcFile(path)
		if err != nil {
			return nil
		}
		results = append(results, r)
		total.lines += r.lines
		total.words += r.words
		total.chars += r.chars
		total.bytes += r.bytes
		return nil
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] %s", dirPath))
	if pattern != "*" {
		sb.WriteString(fmt.Sprintf(" (pattern: %s)", pattern))
	}
	sb.WriteString(fmt.Sprintf(" — %d files\n\n", len(results)))
	sb.WriteString(fmt.Sprintf("  %8s %8s %8s %10s  %s\n", "Lines", "Words", "Chars", "Bytes", "File"))
	sb.WriteString(fmt.Sprintf("  %8s %8s %8s %10s  %s\n", "-----", "-----", "-----", "-----", "----"))

	for _, r := range results {
		sb.WriteString(fmt.Sprintf("  %8d %8d %8d %10d  %s\n", r.lines, r.words, r.chars, r.bytes, r.path))
	}

	if len(results) > 1 {
		sb.WriteString(fmt.Sprintf("  %8s %8s %8s %10s  %s\n", "-----", "-----", "-----", "-----", "----"))
		sb.WriteString(fmt.Sprintf("  %8d %8d %8d %10d  %s\n", total.lines, total.words, total.chars, total.bytes, "total"))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func formatWcResult(r wcResult) string {
	return fmt.Sprintf("[*] %s\n  Lines: %d\n  Words: %d\n  Chars: %d\n  Bytes: %d",
		r.path, r.lines, r.words, r.chars, r.bytes)
}
