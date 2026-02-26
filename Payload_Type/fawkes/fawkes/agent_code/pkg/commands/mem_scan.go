package commands

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// MemScanCommand searches process memory for string or byte patterns
type MemScanCommand struct{}

func (c *MemScanCommand) Name() string        { return "mem-scan" }
func (c *MemScanCommand) Description() string { return "Search process memory for patterns (T1005)" }

type memScanArgs struct {
	PID          int    `json:"pid"`
	Pattern      string `json:"pattern"`
	Hex          bool   `json:"hex"`
	MaxResults   int    `json:"max_results"`
	ContextBytes int    `json:"context_bytes"`
}

// memScanMatch represents a single match found in memory
type memScanMatch struct {
	Address    uint64
	RegionBase uint64
	Context    []byte // bytes around the match
	MatchStart int    // offset of match within context
	MatchLen   int    // length of matched bytes
}

func (c *MemScanCommand) Execute(task structs.Task) structs.CommandResult {
	var args memScanArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Pattern == "" {
		return structs.CommandResult{
			Output:    "Error: pattern is required",
			Status:    "error",
			Completed: true,
		}
	}

	// Default to current process
	if args.PID <= 0 {
		args.PID = os.Getpid()
	}
	if args.MaxResults <= 0 {
		args.MaxResults = 50
	}
	if args.ContextBytes <= 0 {
		args.ContextBytes = 32
	}
	if args.ContextBytes > 256 {
		args.ContextBytes = 256
	}

	// Resolve pattern to bytes
	var searchBytes []byte
	if args.Hex {
		var err error
		searchBytes, err = hex.DecodeString(strings.ReplaceAll(args.Pattern, " ", ""))
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: invalid hex pattern: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	} else {
		searchBytes = []byte(args.Pattern)
	}

	if len(searchBytes) == 0 {
		return structs.CommandResult{
			Output:    "Error: pattern is empty",
			Status:    "error",
			Completed: true,
		}
	}

	// Platform-specific memory scan
	matches, regionsScanned, bytesScanned, err := scanProcessMemory(args.PID, searchBytes, args.MaxResults, args.ContextBytes)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error scanning PID %d: %v", args.PID, err),
			Status:    "error",
			Completed: true,
		}
	}

	return formatMemScanOutput(args, matches, regionsScanned, bytesScanned, searchBytes)
}

// searchInRegion searches a memory region's data for the pattern and returns matches
func searchInRegion(data []byte, regionBase uint64, searchBytes []byte, contextBytes int, maxResults int, matches []memScanMatch) []memScanMatch {
	offset := 0
	for len(matches) < maxResults {
		idx := bytes.Index(data[offset:], searchBytes)
		if idx < 0 {
			break
		}

		absOffset := offset + idx
		matchAddr := regionBase + uint64(absOffset)

		// Extract context around the match
		ctxStart := absOffset - contextBytes
		if ctxStart < 0 {
			ctxStart = 0
		}
		ctxEnd := absOffset + len(searchBytes) + contextBytes
		if ctxEnd > len(data) {
			ctxEnd = len(data)
		}

		matches = append(matches, memScanMatch{
			Address:    matchAddr,
			RegionBase: regionBase,
			Context:    append([]byte{}, data[ctxStart:ctxEnd]...), // copy
			MatchStart: absOffset - ctxStart,
			MatchLen:   len(searchBytes),
		})

		offset = absOffset + len(searchBytes)
		if offset >= len(data) {
			break
		}
	}
	return matches
}

func formatMemScanOutput(args memScanArgs, matches []memScanMatch, regionsScanned int, bytesScanned uint64, searchBytes []byte) structs.CommandResult {
	var sb strings.Builder

	patternDisplay := args.Pattern
	if args.Hex {
		patternDisplay = fmt.Sprintf("0x%s", hex.EncodeToString(searchBytes))
	}

	sb.WriteString(fmt.Sprintf("Memory Scan: PID %d\n", args.PID))
	sb.WriteString(fmt.Sprintf("Pattern: %s (%d bytes)\n", patternDisplay, len(searchBytes)))
	sb.WriteString(fmt.Sprintf("Regions scanned: %d | Bytes scanned: %s\n", regionsScanned, formatScanSize(bytesScanned)))
	sb.WriteString(fmt.Sprintf("Matches found: %d", len(matches)))
	if len(matches) >= args.MaxResults {
		sb.WriteString(" (limit reached, use -max_results to increase)")
	}
	sb.WriteString("\n")

	if len(matches) == 0 {
		return structs.CommandResult{
			Output:    sb.String(),
			Status:    "success",
			Completed: true,
		}
	}

	sb.WriteString(strings.Repeat("-", 80) + "\n\n")

	for i, m := range matches {
		sb.WriteString(fmt.Sprintf("Match %d: 0x%X (region base 0x%X + 0x%X)\n",
			i+1, m.Address, m.RegionBase, m.Address-m.RegionBase))

		// Hex dump with match highlighted
		writeHexDump(&sb, m.Context, m.MatchStart, m.MatchLen, m.Address-uint64(m.MatchStart))
		sb.WriteString("\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// writeHexDump writes a hex dump with ASCII sidebar, highlighting the match
func writeHexDump(sb *strings.Builder, data []byte, matchStart, matchLen int, baseAddr uint64) {
	const bytesPerLine = 16
	for i := 0; i < len(data); i += bytesPerLine {
		end := i + bytesPerLine
		if end > len(data) {
			end = len(data)
		}
		line := data[i:end]

		// Address
		sb.WriteString(fmt.Sprintf("  0x%08X  ", baseAddr+uint64(i)))

		// Hex bytes
		for j, b := range line {
			pos := i + j
			if pos >= matchStart && pos < matchStart+matchLen {
				sb.WriteString(fmt.Sprintf("[%02x]", b))
			} else {
				sb.WriteString(fmt.Sprintf(" %02x ", b))
			}
		}
		// Pad if short line
		for j := len(line); j < bytesPerLine; j++ {
			sb.WriteString("    ")
		}

		// ASCII
		sb.WriteString(" |")
		for _, b := range line {
			if b >= 0x20 && b <= 0x7e {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
}

func formatScanSize(bytes uint64) string {
	if bytes >= 1<<30 {
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(1<<30))
	}
	if bytes >= 1<<20 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(1<<20))
	}
	if bytes >= 1<<10 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(1<<10))
	}
	return fmt.Sprintf("%d B", bytes)
}
