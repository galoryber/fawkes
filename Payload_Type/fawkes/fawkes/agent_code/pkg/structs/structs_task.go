package structs

import (
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// Task represents a task from Mythic
type Task struct {
	ID        string    `json:"id"`
	Command   string    `json:"command"`
	Params    string    `json:"parameters"`
	Timestamp time.Time `json:"timestamp"`
	StartTime time.Time `json:"-"` // When the agent began executing this task
	Job       *Job      `json:"-"` // Not marshalled to JSON
	stopped   *int32    // Atomic flag for task cancellation; pointer so copies share state
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

// WipeParams zeros out the task parameters in memory to reduce forensic exposure.
// Credentials and sensitive arguments are cleared after command execution.
func (t *Task) WipeParams() {
	if len(t.Params) > 0 {
		b := unsafe.Slice(unsafe.StringData(t.Params), len(t.Params))
		clear(b)
	}
	t.Params = ""
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

// Job struct holds channels and state for task execution including file transfers
type Job struct {
	Stop                         *int
	SendResponses                chan Response
	SendFileToMythic             chan SendFileToMythicStruct
	GetFileFromMythic            chan GetFileFromMythicStruct
	FileTransfers                map[string]chan json.RawMessage
	FileTransfersMu              sync.RWMutex
	InteractiveTaskInputChannel  chan InteractiveMsg // Inbound from Mythic → task
	InteractiveTaskOutputChannel chan InteractiveMsg // Outbound from task → Mythic
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

// FileTransferResult holds the result of a completed file transfer
type FileTransferResult struct {
	FileID    string // Mythic file_id
	SHA256    string // SHA256 hash of all transferred data
	BytesSent int64  // Total bytes transferred
	Chunks    int    // Total chunks transferred
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
	TransferResult        *FileTransferResult // Optional: populated on successful completion
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
	TransferResult        *FileTransferResult // Optional: populated on successful completion
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

// FileUploadMessageResponse is the response from Mythic when requesting file chunks
type FileUploadMessageResponse struct {
	ChunkNum    int    `json:"chunk_num"`
	ChunkData   string `json:"chunk_data"`
	TotalChunks int    `json:"total_chunks"`
}
