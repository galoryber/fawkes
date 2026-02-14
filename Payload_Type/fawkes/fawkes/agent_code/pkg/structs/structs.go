package structs

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Agent represents the agent instance
type Agent struct {
	PayloadUUID   string `json:"payload_uuid"`
	Architecture  string `json:"architecture"`
	Domain        string `json:"domain"`
	ExternalIP    string `json:"external_ip"`
	Host          string `json:"host"`
	Integrity     int    `json:"integrity_level"`
	InternalIP    string `json:"internal_ip"`
	OS            string `json:"os"`
	PID           int    `json:"pid"`
	ProcessName   string `json:"process_name"`
	SleepInterval int    `json:"sleep_interval"`
	Jitter        int    `json:"jitter"`
	User          string `json:"user"`
	Description   string `json:"description"`
}

// UpdateSleepParams updates the agent's sleep parameters
func (a *Agent) UpdateSleepParams(interval, jitter int) {
	a.SleepInterval = interval
	a.Jitter = jitter
}

// Task represents a task from Mythic
type Task struct {
	ID         string    `json:"id"`
	Command    string    `json:"command"`
	Params     string    `json:"parameters"`
	Timestamp  time.Time `json:"timestamp"`
	Job        *Job      `json:"-"` // Not marshalled to JSON
	shouldStop bool      // Internal flag for task cancellation
}

// DidStop checks if the task should stop
func (t *Task) DidStop() bool {
	return t.shouldStop
}

// ShouldStop checks if the task should stop (alias for DidStop)
func (t *Task) ShouldStop() bool {
	return t.shouldStop
}

// SetStop sets the stop flag for the task
func (t *Task) SetStop() {
	t.shouldStop = true
}

// NewResponse creates a new response for this task
func (t *Task) NewResponse() Response {
	return Response{
		TaskID: t.ID,
	}
}

// Response represents a response to Mythic
type Response struct {
	TaskID          string               `json:"task_id"`
	UserOutput      string               `json:"user_output"`
	Status          string               `json:"status"`
	Completed       bool                 `json:"completed"`
	ProcessResponse interface{}          `json:"process_response,omitempty"`
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
	Action      string     `json:"action"`
	TaskingSize int        `json:"tasking_size"`
	Socks       []SocksMsg `json:"socks,omitempty"`
	// Add agent identification for checkin updates
	PayloadUUID string `json:"uuid,omitempty"`
	PayloadType string `json:"payload_type,omitempty"`
	C2Profile   string `json:"c2_profile,omitempty"`
}

// PostResponseMessage represents posting a response back to Mythic
type PostResponseMessage struct {
	Action    string     `json:"action"`
	Responses []Response `json:"responses"`
	Socks     []SocksMsg `json:"socks,omitempty"`
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
