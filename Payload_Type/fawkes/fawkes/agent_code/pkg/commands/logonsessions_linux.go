//go:build linux

package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
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

// sessionEntry matches the Windows JSON output structure for browser script compatibility.
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

// utmpEntry represents a parsed utmp record for logonsessions.
type utmpEntry struct {
	Type    int16
	PID     int32
	Line    string
	ID      string
	User    string
	Host    string
	Session int32
	TimeSec int32
	AddrV6  [4]uint32
}

// logonSessionsUtmpPaths lists locations to check for the utmp file.
var logonSessionsUtmpPaths = []string{
	"/var/run/utmp",
	"/run/utmp",
}

// parseUtmpForLogonSessions reads and parses the utmp binary file.
// Reuses utmpRecordSize (384) from linux_logs.go and field size constants
// from last_linux.go.
func parseUtmpForLogonSessions() ([]utmpEntry, error) {
	var data []byte
	var readErr error
	for _, path := range logonSessionsUtmpPaths {
		data, readErr = os.ReadFile(path)
		if readErr == nil {
			break
		}
	}
	if readErr != nil {
		return nil, fmt.Errorf("cannot read utmp: %w", readErr)
	}
	defer structs.ZeroBytes(data) // opsec: utmp contains usernames, session IPs

	if len(data) < utmpRecordSize {
		return nil, nil // empty or too small
	}

	var entries []utmpEntry
	for offset := 0; offset+utmpRecordSize <= len(data); offset += utmpRecordSize {
		rec := data[offset : offset+utmpRecordSize]

		e := utmpEntry{
			Type:    int16(binary.LittleEndian.Uint16(rec[0:2])),
			PID:     int32(binary.LittleEndian.Uint32(rec[4:8])),
			Line:    extractCString(rec[8 : 8+utmpLineSize]),
			ID:      extractCString(rec[40:44]),
			User:    extractCString(rec[44 : 44+utmpUserSize]),
			Host:    extractCString(rec[76 : 76+utmpHostSize]),
			Session: int32(binary.LittleEndian.Uint32(rec[336:340])),
			TimeSec: int32(binary.LittleEndian.Uint32(rec[340:344])),
		}

		// Parse IPv6/IPv4 address
		for i := 0; i < 4; i++ {
			e.AddrV6[i] = binary.LittleEndian.Uint32(rec[348+i*4 : 352+i*4])
		}

		entries = append(entries, e)
	}

	return entries, nil
}

// logonSessionsAddrString formats the address from a utmp entry.
func logonSessionsAddrString(addr [4]uint32) string {
	if addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 {
		return ""
	}
	// IPv4: only first uint32 is set
	if addr[1] == 0 && addr[2] == 0 && addr[3] == 0 {
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, addr[0])
		return ip.String()
	}
	// IPv6: all 4 uint32s form the address
	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(ip[i*4:], addr[i])
	}
	return ip.String()
}

func (c *LogonSessionsCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[logonSessionsArgs](task)
	if parseErr != nil {
		return *parseErr
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

// enumerateLinuxSessions reads utmp and returns session entries.
func enumerateLinuxSessions() ([]sessionEntry, error) {
	utmpEntries, err := parseUtmpForLogonSessions()
	if err != nil {
		return nil, err
	}

	var sessions []sessionEntry
	for _, e := range utmpEntries {
		if e.Type != utUserProc {
			continue
		}
		if e.User == "" {
			continue
		}

		s := sessionEntry{
			SessionID: uint32(e.Session),
			UserName:  e.User,
			Station:   e.Line,
			State:     "Active",
			PID:       e.PID,
		}

		// Set hostname from utmp host field or IP address
		if e.Host != "" {
			s.ClientName = e.Host
		} else if addr := logonSessionsAddrString(e.AddrV6); addr != "" {
			s.ClientName = addr
		}

		// Format login time
		if e.TimeSec > 0 {
			t := time.Unix(int64(e.TimeSec), 0)
			s.LoginTime = t.Format("2006-01-02 15:04:05")
		}

		sessions = append(sessions, s)
	}

	return sessions, nil
}

func logonSessionsList(args logonSessionsArgs) structs.CommandResult {
	sessions, err := enumerateLinuxSessions()
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
	sessions, err := enumerateLinuxSessions()
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
