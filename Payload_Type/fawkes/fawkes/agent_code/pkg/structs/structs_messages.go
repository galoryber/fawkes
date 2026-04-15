package structs

// SocksMsg represents a single SOCKS/rpfwd proxy message exchanged with Mythic.
// Used for both SOCKS5 proxy and reverse port forward (rpfwd) traffic.
type SocksMsg struct {
	ServerId uint32 `json:"server_id"`
	Data     string `json:"data"`
	Exit     bool   `json:"exit"`
	Port     uint32 `json:"port,omitempty"`
}

// InteractiveMsg represents a single interactive tasking message exchanged with Mythic.
// Used for bidirectional PTY/terminal streaming. Data is base64-encoded.
type InteractiveMsg struct {
	TaskID      string `json:"task_id"`
	Data        string `json:"data"`         // base64-encoded payload
	MessageType int    `json:"message_type"` // see InteractiveType constants
}

// Interactive message types (from Mythic docs).
const (
	InteractiveInput  = 0
	InteractiveOutput = 1
	InteractiveError  = 2
	InteractiveExit   = 3
	InteractiveEscape = 4
	InteractiveCtrlA  = 5
	InteractiveCtrlB  = 6
	InteractiveCtrlC  = 7
	InteractiveCtrlD  = 8
	InteractiveCtrlE  = 9
	InteractiveCtrlF  = 10
	InteractiveCtrlG  = 11
	InteractiveCtrlH  = 12 // Backspace
	InteractiveCtrlI  = 13 // Tab
	InteractiveCtrlJ  = 14
	InteractiveCtrlK  = 15
	InteractiveCtrlL  = 16
	InteractiveCtrlM  = 17
	InteractiveCtrlN  = 18
	InteractiveCtrlO  = 19
	InteractiveCtrlP  = 20
	InteractiveCtrlQ  = 21
	InteractiveCtrlR  = 22
	InteractiveCtrlS  = 23
	InteractiveCtrlT  = 24
	InteractiveCtrlU  = 25
	InteractiveCtrlV  = 26
	InteractiveCtrlW  = 27
	InteractiveCtrlX  = 28
	InteractiveCtrlY  = 29
	InteractiveCtrlZ  = 30
)

// DelegateMessage wraps a message to/from a linked P2P agent.
// When sending to Mythic: Message is the base64-encoded encrypted data from the child.
// When receiving from Mythic: Message is the base64-encoded encrypted data for the child.
type DelegateMessage struct {
	Message       string `json:"message"`            // Base64-encoded encrypted message
	UUID          string `json:"uuid"`               // Target agent UUID (or temp UUID during staging)
	C2ProfileName string `json:"c2_profile"`         // C2 profile name (e.g., "tcp")
	MythicUUID    string `json:"new_uuid,omitempty"` // Corrected UUID from Mythic after staging
}

// P2PConnectionMessage notifies Mythic about P2P link state changes (edges in the graph).
type P2PConnectionMessage struct {
	Source        string `json:"source"`      // Source callback UUID
	Destination   string `json:"destination"` // Destination callback UUID
	Action        string `json:"action"`      // "add" or "remove"
	C2ProfileName string `json:"c2_profile"`  // "tcp"
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
	Action      string            `json:"action"`
	TaskingSize int               `json:"tasking_size"`
	Socks       []SocksMsg        `json:"socks,omitempty"`
	Rpfwd       []SocksMsg        `json:"rpfwd,omitempty"`
	Delegates   []DelegateMessage `json:"delegates,omitempty"`
	Interactive []InteractiveMsg  `json:"interactive,omitempty"`
	// Add agent identification for checkin updates
	PayloadUUID string `json:"uuid,omitempty"`
	PayloadType string `json:"payload_type,omitempty"`
	C2Profile   string `json:"c2_profile,omitempty"`
}

// PostResponseMessage represents posting a response back to Mythic
type PostResponseMessage struct {
	Action      string                 `json:"action"`
	Responses   []Response             `json:"responses"`
	Socks       []SocksMsg             `json:"socks,omitempty"`
	Rpfwd       []SocksMsg             `json:"rpfwd,omitempty"`
	Delegates   []DelegateMessage      `json:"delegates,omitempty"`
	Interactive []InteractiveMsg       `json:"interactive,omitempty"`
	Edges       []P2PConnectionMessage `json:"edges,omitempty"`
}
