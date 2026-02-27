package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// HexdumpCommand implements hex dump of file contents
type HexdumpCommand struct{}

func (c *HexdumpCommand) Name() string {
	return "hexdump"
}

func (c *HexdumpCommand) Description() string {
	return "Display hex dump of file contents — binary analysis without downloading"
}

type hexdumpArgs struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"` // byte offset to start from
	Length int    `json:"length"` // number of bytes to read (0 = default 256)
}

const hexdumpMaxLength = 4096 // prevent accidental massive output

func (c *HexdumpCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: no parameters provided",
			Status:    "error",
			Completed: true,
		}
	}

	var args hexdumpArgs
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

	if args.Length == 0 {
		args.Length = 256
	}
	if args.Length > hexdumpMaxLength {
		args.Length = hexdumpMaxLength
	}

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

	fileSize := info.Size()

	// Seek to offset
	if args.Offset > 0 {
		if args.Offset >= fileSize {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: offset %d exceeds file size %d", args.Offset, fileSize),
				Status:    "error",
				Completed: true,
			}
		}
		if _, err := f.Seek(args.Offset, io.SeekStart); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error seeking: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	buf := make([]byte, args.Length)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	buf = buf[:n]

	// Format xxd-style output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] %s (%s) — offset 0x%08x, %d bytes\n",
		args.Path, statFormatSize(fileSize), args.Offset, n))

	for i := 0; i < n; i += 16 {
		// Address
		sb.WriteString(fmt.Sprintf("%08x: ", args.Offset+int64(i)))

		// Hex bytes
		for j := 0; j < 16; j++ {
			if i+j < n {
				sb.WriteString(fmt.Sprintf("%02x ", buf[i+j]))
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteString(" ")
			}
		}

		// ASCII
		sb.WriteString(" |")
		for j := 0; j < 16 && i+j < n; j++ {
			b := buf[i+j]
			if b >= 0x20 && b <= 0x7e {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}
