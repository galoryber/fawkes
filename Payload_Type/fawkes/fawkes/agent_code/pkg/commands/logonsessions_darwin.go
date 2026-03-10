//go:build darwin

package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type LogonSessionsCommand struct{}

func (c *LogonSessionsCommand) Name() string {
	return "logonsessions"
}

func (c *LogonSessionsCommand) Description() string {
	return "Enumerate active logon sessions on the system (T1033)"
}

type logonSessionsArgs struct {
	Action string `json:"action"` // "list" (default) or "users" (unique users only)
	Filter string `json:"filter"` // Optional username filter
}

type sessionEntry struct {
	SessionID  uint32 `json:"session_id"`
	UserName   string `json:"username"`
	Domain     string `json:"domain"`
	Station    string `json:"station"`
	State      string `json:"state"`
	ClientName string `json:"client,omitempty"`
	PID        int32  `json:"pid,omitempty"`
	LoginTime  string `json:"login_time,omitempty"`
}

type userEntry struct {
	User     string   `json:"user"`
	Domain   string   `json:"domain,omitempty"`
	Sessions int      `json:"sessions"`
	Details  []string `json:"details"`
}

// macOS utmpx record layout (628 bytes total):
//
//	Offset  Size  Field
//	0       256   ut_user
//	256     4     ut_id
//	260     32    ut_line
//	292     4     ut_pid
//	296     2     ut_type
//	298     2     (padding)
//	300     4     ut_tv.tv_sec
//	304     4     ut_tv.tv_usec
//	308     256   ut_host
//	564     64    ut_pad[16]
const (
	utmpxRecordSize = 628
	utmpxUserSize   = 256
	utmpxIDSize     = 4
	utmpxLineSize   = 32
	utmpxHostSize   = 256

	utmpxOffsetUser = 0
	utmpxOffsetID   = 256
	utmpxOffsetLine = 260
	utmpxOffsetPID  = 292
	utmpxOffsetType = 296
	utmpxOffsetSec  = 300
	utmpxOffsetHost = 308

	utmpxUserProcess = 7
)

// utmpxEntry represents a parsed macOS utmpx record.
type utmpxEntry struct {
	Type    int16
	PID     int32
	Line    string
	ID      string
	User    string
	Host    string
	TimeSec int32
}

// logonSessionsUtmpxPath is the macOS utmpx file location.
var logonSessionsUtmpxPath = "/var/run/utmpx"

// extractCString extracts a null-terminated C string from a byte slice.
func extractCString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

// parseUtmpxForLogonSessions reads and parses the macOS utmpx binary file.
func parseUtmpxForLogonSessions() ([]utmpxEntry, error) {
	data, err := os.ReadFile(logonSessionsUtmpxPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read utmpx: %v", err)
	}

	if len(data) < utmpxRecordSize {
		return nil, nil
	}

	var entries []utmpxEntry
	for offset := 0; offset+utmpxRecordSize <= len(data); offset += utmpxRecordSize {
		rec := data[offset : offset+utmpxRecordSize]

		e := utmpxEntry{
			User:    extractCString(rec[utmpxOffsetUser : utmpxOffsetUser+utmpxUserSize]),
			ID:      extractCString(rec[utmpxOffsetID : utmpxOffsetID+utmpxIDSize]),
			Line:    extractCString(rec[utmpxOffsetLine : utmpxOffsetLine+utmpxLineSize]),
			PID:     int32(binary.LittleEndian.Uint32(rec[utmpxOffsetPID : utmpxOffsetPID+4])),
			Type:    int16(binary.LittleEndian.Uint16(rec[utmpxOffsetType : utmpxOffsetType+2])),
			TimeSec: int32(binary.LittleEndian.Uint32(rec[utmpxOffsetSec : utmpxOffsetSec+4])),
			Host:    extractCString(rec[utmpxOffsetHost : utmpxOffsetHost+utmpxHostSize]),
		}

		entries = append(entries, e)
	}

	return entries, nil
}

func (c *LogonSessionsCommand) Execute(task structs.Task) structs.CommandResult {
	var args logonSessionsArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Failed to parse parameters: %v", err)
		}
	}

	action := strings.ToLower(args.Action)
	if action == "" {
		action = "list"
	}

	switch action {
	case "list":
		return logonSessionsList(args)
	case "users":
		return logonSessionsUsers(args)
	default:
		return errorf("Unknown action: %s. Use: list, users", action)
	}
}

// enumerateDarwinSessions reads utmpx and returns session entries.
func enumerateDarwinSessions() ([]sessionEntry, error) {
	utmpxEntries, err := parseUtmpxForLogonSessions()
	if err != nil {
		return nil, err
	}

	var sessions []sessionEntry
	for _, e := range utmpxEntries {
		if e.Type != utmpxUserProcess {
			continue
		}
		if e.User == "" {
			continue
		}

		s := sessionEntry{
			UserName: e.User,
			Station:  e.Line,
			State:    "Active",
			PID:      e.PID,
		}

		if e.Host != "" {
			s.ClientName = e.Host
		}

		if e.TimeSec > 0 {
			t := time.Unix(int64(e.TimeSec), 0)
			s.LoginTime = t.Format("2006-01-02 15:04:05")
		}

		sessions = append(sessions, s)
	}

	return sessions, nil
}

func logonSessionsList(args logonSessionsArgs) structs.CommandResult {
	sessions, err := enumerateDarwinSessions()
	if err != nil {
		return errorf("Error: %v", err)
	}

	var filtered []sessionEntry
	for _, s := range sessions {
		if args.Filter != "" {
			filterLower := strings.ToLower(args.Filter)
			if !strings.Contains(strings.ToLower(s.UserName), filterLower) {
				continue
			}
		}
		filtered = append(filtered, s)
	}

	if len(filtered) == 0 {
		return successResult("[]")
	}

	data, err := json.Marshal(filtered)
	if err != nil {
		return errorf("Error marshaling output: %v", err)
	}

	return successResult(string(data))
}

func logonSessionsUsers(args logonSessionsArgs) structs.CommandResult {
	sessions, err := enumerateDarwinSessions()
	if err != nil {
		return errorf("Error: %v", err)
	}

	type userInfo struct {
		Sessions map[string]string // terminal → state
	}

	users := make(map[string]*userInfo)

	for _, s := range sessions {
		if s.UserName == "" {
			continue
		}

		if args.Filter != "" {
			filterLower := strings.ToLower(args.Filter)
			if !strings.Contains(strings.ToLower(s.UserName), filterLower) {
				continue
			}
		}

		if entry, ok := users[s.UserName]; ok {
			entry.Sessions[s.Station] = s.State
		} else {
			users[s.UserName] = &userInfo{
				Sessions: map[string]string{s.Station: s.State},
			}
		}
	}

	if len(users) == 0 {
		return successResult("[]")
	}

	var entries []userEntry
	for name, info := range users {
		var details []string
		for terminal, state := range info.Sessions {
			details = append(details, fmt.Sprintf("%s(%s)", terminal, state))
		}
		entries = append(entries, userEntry{
			User:     name,
			Sessions: len(info.Sessions),
			Details:  details,
		})
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return errorf("Error marshaling output: %v", err)
	}

	return successResult(string(data))
}
