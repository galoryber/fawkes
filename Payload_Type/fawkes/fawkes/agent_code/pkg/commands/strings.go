package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// StringsCommand extracts printable strings from files
type StringsCommand struct{}

func (c *StringsCommand) Name() string {
	return "strings"
}

func (c *StringsCommand) Description() string {
	return "Extract printable strings from files — find embedded text, URLs, credentials in binaries"
}

type stringsArgs struct {
	Path    string `json:"path"`
	MinLen  int    `json:"min_length"` // minimum string length (default 4)
	Offset  int64  `json:"offset"`     // byte offset to start from
	MaxSize int64  `json:"max_size"`   // max bytes to scan (default 10MB)
	Pattern string `json:"pattern"`    // filter: only show strings containing this
}

const (
	stringsDefaultMinLen  = 4
	stringsDefaultMaxSize = 10 * 1024 * 1024 // 10MB
	stringsMaxOutput      = 100000           // max output chars to prevent huge responses
)

func (c *StringsCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: no parameters provided")
	}

	var args stringsArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		args.Path = strings.TrimSpace(task.Params)
	}

	if args.Path == "" {
		return errorResult("Error: path is required")
	}

	if args.MinLen <= 0 {
		args.MinLen = stringsDefaultMinLen
	}
	if args.MaxSize <= 0 {
		args.MaxSize = stringsDefaultMaxSize
	}

	f, err := os.Open(args.Path)
	if err != nil {
		return errorf("Error opening file: %v", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return errorf("Error stating file: %v", err)
	}

	fileSize := info.Size()

	if args.Offset > 0 {
		if args.Offset >= fileSize {
			return errorf("Error: offset %d exceeds file size %d", args.Offset, fileSize)
		}
		if _, err := f.Seek(args.Offset, io.SeekStart); err != nil {
			return errorf("Error seeking: %v", err)
		}
	}

	scanSize := fileSize - args.Offset
	if scanSize > args.MaxSize {
		scanSize = args.MaxSize
	}

	reader := io.LimitReader(f, scanSize)
	found := extractStrings(reader, args.MinLen, args.Pattern)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] %s (%s) — min length %d, scanned %s",
		args.Path, formatFileSize(fileSize), args.MinLen, formatFileSize(scanSize)))
	if args.Pattern != "" {
		sb.WriteString(fmt.Sprintf(", filter: %q", args.Pattern))
	}
	sb.WriteString(fmt.Sprintf("\n[*] Found %d strings\n\n", len(found)))

	outputLen := 0
	truncated := false
	for i, s := range found {
		line := fmt.Sprintf("%d: %s\n", i+1, s)
		if outputLen+len(line) > stringsMaxOutput {
			truncated = true
			break
		}
		sb.WriteString(line)
		outputLen += len(line)
	}

	if truncated {
		sb.WriteString(fmt.Sprintf("\n[!] Output truncated (showing partial results of %d strings)\n", len(found)))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// extractStrings scans a reader for sequences of printable ASCII characters
func extractStrings(r io.Reader, minLen int, pattern string) []string {
	var result []string
	var current []byte

	br := bufio.NewReaderSize(r, 32768)
	patternLower := strings.ToLower(pattern)

	for {
		b, err := br.ReadByte()
		if err != nil {
			// Flush any pending string
			if len(current) >= minLen {
				s := string(current)
				if pattern == "" || strings.Contains(strings.ToLower(s), patternLower) {
					result = append(result, s)
				}
			}
			break
		}

		if b >= 0x20 && b <= 0x7e {
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				s := string(current)
				if pattern == "" || strings.Contains(strings.ToLower(s), patternLower) {
					result = append(result, s)
				}
			}
			current = current[:0]
		}
	}

	return result
}
