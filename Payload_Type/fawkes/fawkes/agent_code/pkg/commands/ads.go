//go:build windows
// +build windows

package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type ADSCommand struct{}

func (c *ADSCommand) Name() string        { return "ads" }
func (c *ADSCommand) Description() string { return "Manage NTFS Alternate Data Streams (T1564.004)" }

type adsArgs struct {
	Action string `json:"action"` // write, read, list, delete
	File   string `json:"file"`   // target file path
	Stream string `json:"stream"` // stream name (without the colon)
	Data   string `json:"data"`   // data to write (for write action)
	Hex    bool   `json:"hex"`    // if true, data is hex-encoded (for binary)
}

func (c *ADSCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -action <write|read|list|delete> -file <path> [-stream <name>] [-data <content>]",
			Status:    "error",
			Completed: true,
		}
	}

	var args adsArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.File == "" {
		return structs.CommandResult{
			Output:    "Error: file path is required",
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "write":
		return adsWrite(args)
	case "read":
		return adsRead(args)
	case "list":
		return adsList(args)
	case "delete":
		return adsDelete(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown action %q (use write, read, list, delete)", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func adsWrite(args adsArgs) structs.CommandResult {
	if args.Stream == "" {
		return structs.CommandResult{
			Output:    "Error: stream name is required for write action",
			Status:    "error",
			Completed: true,
		}
	}
	if args.Data == "" {
		return structs.CommandResult{
			Output:    "Error: data is required for write action",
			Status:    "error",
			Completed: true,
		}
	}

	var writeData []byte
	if args.Hex {
		var err error
		writeData, err = hex.DecodeString(args.Data)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error decoding hex data: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	} else {
		writeData = []byte(args.Data)
	}

	streamPath := args.File + ":" + args.Stream
	if err := os.WriteFile(streamPath, writeData, 0644); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing to %s: %v", streamPath, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Wrote %d bytes to %s", len(writeData), streamPath),
		Status:    "success",
		Completed: true,
	}
}

func adsRead(args adsArgs) structs.CommandResult {
	if args.Stream == "" {
		return structs.CommandResult{
			Output:    "Error: stream name is required for read action",
			Status:    "error",
			Completed: true,
		}
	}

	streamPath := args.File + ":" + args.Stream
	data, err := os.ReadFile(streamPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading %s: %v", streamPath, err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Stream: %s (%d bytes)\n", streamPath, len(data)))
	sb.WriteString(strings.Repeat("=", 50) + "\n")

	if args.Hex {
		sb.WriteString(hex.Dump(data))
	} else {
		// Check if data is printable
		printable := true
		for _, b := range data {
			if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
				printable = false
				break
			}
		}
		if printable {
			sb.Write(data)
		} else {
			sb.WriteString("(binary data — use -hex true to see hex dump)\n")
			sb.WriteString(hex.Dump(data[:min(len(data), 256)]))
			if len(data) > 256 {
				sb.WriteString(fmt.Sprintf("... (%d more bytes)\n", len(data)-256))
			}
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// WIN32_FIND_STREAM_DATA structure
type findStreamData struct {
	StreamSize int64
	StreamName [296]uint16 // MAX_PATH + 36
}

var (
	kernel32ADS             = windows.NewLazySystemDLL("kernel32.dll")
	procFindFirstStreamW    = kernel32ADS.NewProc("FindFirstStreamW")
	procFindNextStreamW     = kernel32ADS.NewProc("FindNextStreamW")
	procFindCloseADS        = kernel32ADS.NewProc("FindClose")
)

func adsList(args adsArgs) structs.CommandResult {
	// Resolve to absolute path
	absPath, err := filepath.Abs(args.File)
	if err != nil {
		absPath = args.File
	}

	// Check if file exists
	info, err := os.Stat(absPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// If directory, list ADS on all files in the directory
	if info.IsDir() {
		return adsListDir(absPath)
	}

	return adsListFile(absPath)
}

func adsListFile(filePath string) structs.CommandResult {
	streams, err := adsEnumerateStreams(filePath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating streams for %s: %v", filePath, err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Alternate Data Streams for: %s\n", filePath))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	if len(streams) == 0 {
		sb.WriteString("No alternate data streams found.\n")
	} else {
		for _, s := range streams {
			sb.WriteString(fmt.Sprintf("  %s  (%d bytes)\n", s.name, s.size))
		}
		// Count non-default streams
		altCount := 0
		for _, s := range streams {
			if s.name != "::$DATA" {
				altCount++
			}
		}
		sb.WriteString(fmt.Sprintf("\n%d stream(s) total, %d alternate\n", len(streams), altCount))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func adsListDir(dirPath string) structs.CommandResult {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading directory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Alternate Data Streams in: %s\n", dirPath))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	filesWithADS := 0
	totalADS := 0

	for _, entry := range entries {
		fullPath := filepath.Join(dirPath, entry.Name())
		streams, err := adsEnumerateStreams(fullPath)
		if err != nil {
			continue
		}

		// Count alternate streams (exclude ::$DATA which is the default)
		altStreams := 0
		for _, s := range streams {
			if s.name != "::$DATA" {
				altStreams++
			}
		}

		if altStreams > 0 {
			filesWithADS++
			sb.WriteString(fmt.Sprintf("\n%s:\n", entry.Name()))
			for _, s := range streams {
				if s.name != "::$DATA" {
					sb.WriteString(fmt.Sprintf("  %s  (%d bytes)\n", s.name, s.size))
					totalADS++
				}
			}
		}
	}

	if filesWithADS == 0 {
		sb.WriteString("\nNo files with alternate data streams found.\n")
	} else {
		sb.WriteString(fmt.Sprintf("\n%d file(s) with %d alternate stream(s)\n", filesWithADS, totalADS))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

type adsStreamInfo struct {
	name string
	size int64
}

func adsEnumerateStreams(filePath string) ([]adsStreamInfo, error) {
	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return nil, err
	}

	var fsd findStreamData
	handle, _, callErr := procFindFirstStreamW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0, // FindStreamInfoStandard
		uintptr(unsafe.Pointer(&fsd)),
		0,
	)

	if handle == uintptr(windows.InvalidHandle) {
		// ERROR_HANDLE_EOF means no streams (normal for some files)
		if callErr == syscall.Errno(38) { // ERROR_HANDLE_EOF
			return nil, nil
		}
		return nil, callErr
	}
	defer func() { _, _, _ = procFindCloseADS.Call(handle) }()

	var streams []adsStreamInfo
	streamName := windows.UTF16ToString(fsd.StreamName[:])
	streams = append(streams, adsStreamInfo{name: streamName, size: fsd.StreamSize})

	for {
		var nextFsd findStreamData
		ret, _, callErr := procFindNextStreamW.Call(
			handle,
			uintptr(unsafe.Pointer(&nextFsd)),
		)
		if ret == 0 {
			if callErr == syscall.Errno(38) || callErr == syscall.Errno(18) { // ERROR_HANDLE_EOF or ERROR_NO_MORE_FILES
				break
			}
			break
		}
		nextName := windows.UTF16ToString(nextFsd.StreamName[:])
		streams = append(streams, adsStreamInfo{name: nextName, size: nextFsd.StreamSize})
	}

	return streams, nil
}

func adsDelete(args adsArgs) structs.CommandResult {
	if args.Stream == "" {
		return structs.CommandResult{
			Output:    "Error: stream name is required for delete action",
			Status:    "error",
			Completed: true,
		}
	}

	streamPath := args.File + ":" + args.Stream
	if err := os.Remove(streamPath); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error deleting %s: %v", streamPath, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Deleted stream: %s", streamPath),
		Status:    "success",
		Completed: true,
	}
}

