package structs

import "time"

// Agent represents the agent instance
type Agent struct {
	PayloadUUID     string `json:"payload_uuid"`
	Architecture    string `json:"architecture"`
	Domain          string `json:"domain"`
	ExternalIP      string `json:"external_ip"`
	Host            string `json:"host"`
	Integrity       int    `json:"integrity_level"`
	InternalIP      string `json:"internal_ip"`
	OS              string `json:"os"`
	PID             int    `json:"pid"`
	ProcessName     string `json:"process_name"`
	SleepInterval   int    `json:"sleep_interval"`
	Jitter          int    `json:"jitter"`
	User            string `json:"user"`
	Description     string `json:"description"`
}

// Task represents a task from Mythic
type Task struct {
	ID       string `json:"id"`
	Command  string `json:"command"`
	Params   string `json:"parameters"`
	Timestamp time.Time `json:"timestamp"`
}

// Response represents a response to Mythic
type Response struct {
	TaskID      string `json:"task_id"`
	UserOutput  string `json:"user_output"`
	Status      string `json:"status"`
	Completed   bool   `json:"completed"`
	ProcessResponse interface{} `json:"process_response,omitempty"`
}

// CommandResult represents the result of executing a command
type CommandResult struct {
	Output    string
	Status    string
	Completed bool
}

// CheckinMessage represents the initial checkin message
type CheckinMessage struct {
	Action       string `json:"action"`
	PayloadUUID  string `json:"uuid"`
	User         string `json:"user"`
	Host         string `json:"host"`
	PID          int    `json:"pid"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Domain       string `json:"domain"`
	InternalIP   string `json:"internal_ip"`
	ExternalIP   string `json:"external_ip"`
	ProcessName  string `json:"process_name"`
	Integrity    int    `json:"integrity_level"`
	PayloadType  string `json:"payload_type"`
	C2Profile    string `json:"c2_profile"`
}

// TaskingMessage represents the message to get tasking
type TaskingMessage struct {
	Action string `json:"action"`
	TaskingSize int `json:"tasking_size"`
}

// PostResponseMessage represents posting a response back to Mythic  
type PostResponseMessage struct {
	Action string `json:"action"`
	Responses []Response `json:"responses"`
}

// Command interface for all commands
type Command interface {
	Name() string
	Description() string
	Execute(task Task) CommandResult
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