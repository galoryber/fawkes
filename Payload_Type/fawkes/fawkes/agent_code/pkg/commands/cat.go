package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// CatCommand implements the cat command
type CatCommand struct{}

// Name returns the command name
func (c *CatCommand) Name() string {
	return "cat"
}

// Description returns the command description
func (c *CatCommand) Description() string {
	return "Display file contents with optional line range, numbering, and size protection"
}

// catParams represents the structured parameters for cat
type catParams struct {
	Path   string `json:"path"`
	Start  int    `json:"start"`  // Starting line number (1-based, 0 = beginning)
	End    int    `json:"end"`    // Ending line number (0 = end of file)
	Number bool   `json:"number"` // Show line numbers
	Max    int    `json:"max"`    // Max output size in KB (default 5120 = 5MB)
}

// maxCatBytes is the default maximum output size (5MB)
const maxCatBytes = 5 * 1024 * 1024

// Execute executes the cat command
func (c *CatCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: No file path specified")
	}

	args := catParams{}
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Plain text — treat entire input as file path
		args.Path = stripPathQuotes(task.Params)
	}

	if args.Path == "" {
		return errorResult("Error: No file path specified")
	}

	// Determine max output size
	maxBytes := maxCatBytes
	if args.Max > 0 {
		maxBytes = args.Max * 1024
	}

	// If line range or numbering requested, use line-based reading
	if args.Start > 0 || args.End > 0 || args.Number {
		return catReadLines(args, maxBytes)
	}

	return catReadFull(args.Path, maxBytes)
}

// catReadFull reads the entire file with size protection
func catReadFull(path string, maxBytes int) structs.CommandResult {
	info, err := os.Stat(path)
	if err != nil {
		return errorf("Error: %v", err)
	}

	if info.IsDir() {
		return errorf("Error: %s is a directory", path)
	}

	size := info.Size()

	// Size protection: don't read files larger than maxBytes
	if size > int64(maxBytes) {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error: file is %s (limit: %s). Use 'tail' for large files, or 'cat -max %d' to override.",
				formatFileSize(size), formatFileSize(int64(maxBytes)), (size/1024)+1),
			Status:    "error",
			Completed: true,
		}
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return errorf("Error reading file: %v", err)
	}

	return successResult(string(content))
}

// catReadLines reads specific line ranges with optional numbering
func catReadLines(args catParams, maxBytes int) structs.CommandResult {
	f, err := os.Open(args.Path)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer f.Close()

	info, _ := f.Stat()
	if info != nil && info.IsDir() {
		return errorf("Error: %s is a directory", args.Path)
	}

	scanner := bufio.NewScanner(f)
	// Increase max token size for files with very long lines
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var sb strings.Builder
	lineNum := 0
	outputLines := 0
	startLine := args.Start
	if startLine < 1 {
		startLine = 1
	}
	endLine := args.End // 0 means no limit

	for scanner.Scan() {
		lineNum++

		if lineNum < startLine {
			continue
		}
		if endLine > 0 && lineNum > endLine {
			break
		}

		if sb.Len() > maxBytes {
			sb.WriteString(fmt.Sprintf("\n... (output truncated at %s)", formatFileSize(int64(maxBytes))))
			break
		}

		if args.Number {
			sb.WriteString(fmt.Sprintf("%6d  %s\n", lineNum, scanner.Text()))
		} else {
			sb.WriteString(scanner.Text())
			sb.WriteByte('\n')
		}
		outputLines++
	}

	if err := scanner.Err(); err != nil {
		return errorf("Error reading file: %v", err)
	}

	// Add header for range/numbered output
	header := ""
	if args.Start > 0 || args.End > 0 {
		if args.End > 0 {
			header = fmt.Sprintf("[*] %s lines %d-%d (%d lines shown)\n", args.Path, startLine, min(lineNum, endLine), outputLines)
		} else {
			header = fmt.Sprintf("[*] %s from line %d (%d lines shown)\n", args.Path, startLine, outputLines)
		}
	} else if args.Number {
		header = fmt.Sprintf("[*] %s (%d lines)\n", args.Path, outputLines)
	}

	return successResult(header + sb.String())
}
