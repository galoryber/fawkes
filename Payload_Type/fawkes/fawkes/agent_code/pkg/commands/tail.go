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

// TailCommand implements the tail command for reading portions of files
type TailCommand struct{}

func (c *TailCommand) Name() string {
	return "tail"
}

func (c *TailCommand) Description() string {
	return "Read the first or last N lines of a file — avoids transferring entire large files"
}

type tailArgs struct {
	Path  string `json:"path"`
	Lines int    `json:"lines"`
	Head  bool   `json:"head"`
	Bytes int    `json:"bytes"`
}

func (c *TailCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: no parameters provided",
			Status:    "error",
			Completed: true,
		}
	}

	var args tailArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Path == "" {
		return structs.CommandResult{
			Output:    "Error: path is required",
			Status:    "error",
			Completed: true,
		}
	}

	// Default to 10 lines if neither lines nor bytes specified
	if args.Lines == 0 && args.Bytes == 0 {
		args.Lines = 10
	}

	// Bytes mode: read raw bytes from start or end of file
	if args.Bytes > 0 {
		return tailReadBytes(args)
	}

	// Lines mode
	return tailReadLines(args)
}

func tailReadBytes(args tailArgs) structs.CommandResult {
	f, err := os.Open(args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error stating file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	size := info.Size()
	readSize := int64(args.Bytes)
	if readSize > size {
		readSize = size
	}

	buf := make([]byte, readSize)

	if args.Head {
		// Read from beginning
		_, err = io.ReadFull(f, buf)
	} else {
		// Read from end
		_, err = f.ReadAt(buf, size-readSize)
	}
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	mode := "last"
	if args.Head {
		mode = "first"
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] %s %d bytes of %s (%s total)\n%s",
			mode, readSize, args.Path, statFormatSize(size), string(buf)),
		Status:    "success",
		Completed: true,
	}
}

func tailReadLines(args tailArgs) structs.CommandResult {
	f, err := os.Open(args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer f.Close()

	if args.Head {
		return tailReadHead(f, args)
	}
	return tailReadTail(f, args)
}

func tailReadHead(f *os.File, args tailArgs) structs.CommandResult {
	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) >= args.Lines {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	info, _ := f.Stat()
	sizeStr := ""
	if info != nil {
		sizeStr = fmt.Sprintf(" (%s)", statFormatSize(info.Size()))
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] first %d lines of %s%s\n%s",
			len(lines), args.Path, sizeStr, strings.Join(lines, "\n")),
		Status:    "success",
		Completed: true,
	}
}

func tailReadTail(f *os.File, args tailArgs) structs.CommandResult {
	// Read all lines then take the last N
	// For very large files, a reverse-seek approach would be better,
	// but this is simpler and handles most operational cases
	info, _ := f.Stat()

	// For files > 10MB, use reverse-seek approach to avoid loading entire file
	if info != nil && info.Size() > 10*1024*1024 {
		return tailReadTailLarge(f, args, info.Size())
	}

	scanner := bufio.NewScanner(f)
	// Ring buffer to hold last N lines
	ring := make([]string, args.Lines)
	idx := 0
	total := 0
	for scanner.Scan() {
		ring[idx%args.Lines] = scanner.Text()
		idx++
		total++
	}
	if err := scanner.Err(); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Extract lines in order from ring buffer
	count := args.Lines
	if total < count {
		count = total
	}
	lines := make([]string, count)
	start := idx - count
	for i := 0; i < count; i++ {
		lines[i] = ring[(start+i)%args.Lines]
	}

	sizeStr := ""
	if info != nil {
		sizeStr = fmt.Sprintf(" (%s)", statFormatSize(info.Size()))
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] last %d lines of %s%s\n%s",
			count, args.Path, sizeStr, strings.Join(lines, "\n")),
		Status:    "success",
		Completed: true,
	}
}

func tailReadTailLarge(f *os.File, args tailArgs, size int64) structs.CommandResult {
	// For large files, read backwards from the end in chunks
	chunkSize := int64(8192)
	offset := size
	var tailBytes []byte
	newlineCount := 0
	needed := args.Lines + 1 // +1 because we split on newlines

	for offset > 0 && newlineCount < needed {
		readSize := chunkSize
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize

		buf := make([]byte, readSize)
		_, err := f.ReadAt(buf, offset)
		if err != nil && err != io.EOF {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error reading file: %v", err),
				Status:    "error",
				Completed: true,
			}
		}

		tailBytes = append(buf, tailBytes...)
		for _, b := range buf {
			if b == '\n' {
				newlineCount++
			}
		}
	}

	allLines := strings.Split(string(tailBytes), "\n")
	// Remove trailing empty string from final newline
	if len(allLines) > 0 && allLines[len(allLines)-1] == "" {
		allLines = allLines[:len(allLines)-1]
	}

	count := args.Lines
	if len(allLines) < count {
		count = len(allLines)
	}
	lines := allLines[len(allLines)-count:]

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] last %d lines of %s (%s)\n%s",
			count, args.Path, statFormatSize(size), strings.Join(lines, "\n")),
		Status:    "success",
		Completed: true,
	}
}
