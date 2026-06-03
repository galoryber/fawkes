package structs

import (
	"time"
	"unsafe"
)

// ProcessEntry represents a process for Mythic's process browser
type ProcessEntry struct {
	ProcessID       int    `json:"process_id"`
	ParentProcessID int    `json:"parent_process_id"`
	Architecture    string `json:"architecture"`
	Name            string `json:"name"`
	User            string `json:"user"`
	BinPath         string `json:"bin_path"`
	CommandLine     string `json:"command_line,omitempty"`
	IntegrityLevel  int    `json:"integrity_level,omitempty"`
	StartTime       int64  `json:"start_time,omitempty"`
}

// MythicCredential represents a credential to store in Mythic's credential vault.
// Included in the Response.Credentials array — Mythic automatically ingests these.
type MythicCredential struct {
	CredentialType string `json:"credential_type"` // "plaintext", "hash", "ticket", "key", "certificate"
	Realm          string `json:"realm"`           // Domain/realm (e.g., "CONTOSO.LOCAL")
	Account        string `json:"account"`         // Username
	Credential     string `json:"credential"`      // The actual credential value (password, hash, ticket)
	Comment        string `json:"comment"`         // Source info (e.g., "hashdump", "kerberoast")
}

// Response represents a response to Mythic
type Response struct {
	TaskID          string               `json:"task_id"`
	UserOutput      string               `json:"user_output"`
	Status          string               `json:"status"`
	Completed       bool                 `json:"completed"`
	ProcessResponse interface{}          `json:"process_response,omitempty"`
	Processes       *[]ProcessEntry      `json:"processes,omitempty"`
	Credentials     *[]MythicCredential  `json:"credentials,omitempty"`
	Upload          *FileUploadMessage   `json:"upload,omitempty"`
	Download        *FileDownloadMessage `json:"download,omitempty"`
}

// CommandResult represents the result of executing a command
type CommandResult struct {
	Output      string
	Status      string
	Completed   bool
	Processes   *[]ProcessEntry     // Optional: populated by ps command for Mythic process browser
	Credentials *[]MythicCredential // Optional: credentials to store in Mythic's credential vault
}

// Wipe zeros credential secrets in the Response after transmission.
// Only zeros the Credential field (passwords/hashes) — other fields like
// CredentialType, Account, Realm may be string literals in read-only memory
// and zeroing them crashes with SIGBUS on ARM64 (not recoverable).
func (r *Response) Wipe() {
	r.UserOutput = ""
	if r.Credentials != nil {
		for i := range *r.Credentials {
			zeroString(&(*r.Credentials)[i].Credential)
			(*r.Credentials)[i].Account = ""
			(*r.Credentials)[i].Realm = ""
			(*r.Credentials)[i].Comment = ""
			(*r.Credentials)[i].CredentialType = ""
		}
		r.Credentials = nil
	}
	r.ProcessResponse = nil
	r.Processes = nil
}

// Wipe zeros credential secrets in the CommandResult after use.
func (cr *CommandResult) Wipe() {
	cr.Output = ""
	if cr.Credentials != nil {
		for i := range *cr.Credentials {
			zeroString(&(*cr.Credentials)[i].Credential)
			(*cr.Credentials)[i].Account = ""
			(*cr.Credentials)[i].Realm = ""
			(*cr.Credentials)[i].Comment = ""
			(*cr.Credentials)[i].CredentialType = ""
		}
		cr.Credentials = nil
	}
	cr.Processes = nil
}

// zeroString zeros the backing memory of a heap-allocated string.
// ONLY call on strings known to be heap-allocated (JSON-unmarshaled values,
// password strings from user input, fmt.Sprintf results with dynamic data).
// NEVER call on string literals, constants, or fields that may hold compile-time
// strings — these live in read-only .rodata and cause unrecoverable SIGBUS on ARM64.
func zeroString(s *string) {
	if len(*s) > 0 {
		b := unsafe.Slice(unsafe.StringData(*s), len(*s))
		clear(b)
	}
	*s = ""
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
