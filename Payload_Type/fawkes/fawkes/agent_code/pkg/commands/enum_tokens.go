//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type EnumTokensCommand struct{}

func (c *EnumTokensCommand) Name() string {
	return "enum-tokens"
}

func (c *EnumTokensCommand) Description() string {
	return "Enumerate access tokens across all accessible processes"
}

type enumTokensArgs struct {
	Action string `json:"action"`
	User   string `json:"user"`
}

type tokenEntry struct {
	PID       uint32
	Process   string
	User      string
	Integrity string
	Session   uint32
}

func (c *EnumTokensCommand) Execute(task structs.Task) structs.CommandResult {
	var args enumTokensArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Action == "" {
		args.Action = "list"
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return enumTokensList(args.User)
	case "unique":
		return enumTokensUnique(args.User)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Available: list, unique", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// enumTokensList enumerates all processes and shows their token information
func enumTokensList(filterUser string) structs.CommandResult {
	// Enable SeDebugPrivilege for access to more processes
	enableDebugPrivilege()

	entries, err := enumerateProcessTokens()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to enumerate processes: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Filter by user if specified
	if filterUser != "" {
		var filtered []tokenEntry
		filterLower := strings.ToLower(filterUser)
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.User), filterLower) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	// Sort by user then PID
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].User != entries[j].User {
			return entries[i].User < entries[j].User
		}
		return entries[i].PID < entries[j].PID
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Tokens enumerated: %d processes\n", len(entries)))
	if filterUser != "" {
		sb.WriteString(fmt.Sprintf("Filter: %s\n", filterUser))
	}
	sb.WriteString("\n")

	sb.WriteString(fmt.Sprintf("%-8s %-30s %-35s %-10s %-8s\n", "PID", "PROCESS", "USER", "INTEGRITY", "SESSION"))
	sb.WriteString(strings.Repeat("-", 95) + "\n")

	for _, e := range entries {
		sb.WriteString(fmt.Sprintf("%-8d %-30s %-35s %-10s %-8d\n",
			e.PID, truncateStr(e.Process, 30), truncateStr(e.User, 35), e.Integrity, e.Session))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// enumTokensUnique shows unique user tokens with process counts
func enumTokensUnique(filterUser string) structs.CommandResult {
	enableDebugPrivilege()

	entries, err := enumerateProcessTokens()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to enumerate processes: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Group by user
	type userInfo struct {
		User      string
		Integrity string
		Count     int
		Sessions  map[uint32]bool
		Processes []string
	}
	users := make(map[string]*userInfo)

	for _, e := range entries {
		key := e.User
		if filterUser != "" && !strings.Contains(strings.ToLower(key), strings.ToLower(filterUser)) {
			continue
		}
		if _, ok := users[key]; !ok {
			users[key] = &userInfo{
				User:      e.User,
				Integrity: e.Integrity,
				Sessions:  make(map[uint32]bool),
			}
		}
		u := users[key]
		u.Count++
		u.Sessions[e.Session] = true
		// Track up to 5 unique process names
		if len(u.Processes) < 5 {
			found := false
			for _, p := range u.Processes {
				if p == e.Process {
					found = true
					break
				}
			}
			if !found {
				u.Processes = append(u.Processes, e.Process)
			}
		}
		// Use highest integrity
		if integrityRank(e.Integrity) > integrityRank(u.Integrity) {
			u.Integrity = e.Integrity
		}
	}

	// Sort by user
	var sortedUsers []*userInfo
	for _, u := range users {
		sortedUsers = append(sortedUsers, u)
	}
	sort.Slice(sortedUsers, func(i, j int) bool {
		return sortedUsers[i].User < sortedUsers[j].User
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Unique token owners: %d\n\n", len(sortedUsers)))

	sb.WriteString(fmt.Sprintf("%-35s %-10s %-8s %-10s %s\n", "USER", "INTEGRITY", "PROCS", "SESSIONS", "EXAMPLE PROCESSES"))
	sb.WriteString(strings.Repeat("-", 110) + "\n")

	for _, u := range sortedUsers {
		sessions := make([]string, 0, len(u.Sessions))
		for s := range u.Sessions {
			sessions = append(sessions, fmt.Sprintf("%d", s))
		}
		sort.Strings(sessions)

		sb.WriteString(fmt.Sprintf("%-35s %-10s %-8d %-10s %s\n",
			truncateStr(u.User, 35),
			u.Integrity,
			u.Count,
			strings.Join(sessions, ","),
			strings.Join(u.Processes, ", ")))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// enumerateProcessTokens walks all processes and reads their token info
func enumerateProcessTokens() ([]tokenEntry, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, fmt.Errorf("Process32First: %v", err)
	}

	var entries []tokenEntry

	for {
		pid := entry.ProcessID
		name := windows.UTF16ToString(entry.ExeFile[:])

		if pid > 0 { // Skip Idle process
			te := tokenEntry{
				PID:     pid,
				Process: name,
			}

			// Try to read token info
			if pid == 4 {
				// System process - can't open normally
				te.User = "NT AUTHORITY\\SYSTEM"
				te.Integrity = "System"
				te.Session = 0
			} else {
				user, integrity, session, tokenErr := getProcessTokenInfo(pid)
				if tokenErr == nil {
					te.User = user
					te.Integrity = integrity
					te.Session = session
				} else {
					te.User = "(access denied)"
					te.Integrity = "-"
				}
			}

			entries = append(entries, te)
		}

		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	return entries, nil
}

// getProcessTokenInfo opens a process and reads its token user, integrity, and session
func getProcessTokenInfo(pid uint32) (string, string, uint32, error) {
	hProcess, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", "", 0, err
	}
	defer windows.CloseHandle(hProcess)

	var token windows.Token
	err = windows.OpenProcessToken(hProcess, TOKEN_QUERY, &token)
	if err != nil {
		return "", "", 0, err
	}
	defer token.Close()

	// Get user
	user, err := GetTokenUserInfo(token)
	if err != nil {
		user = "(unknown)"
	}

	// Get integrity using whoami_windows.go's getTokenIntegrityLevel
	integrity, err := getTokenIntegrityLevel(token)
	if err != nil {
		integrity = "Unknown"
	}
	// Extract just the level name (strip the SID suffix like " (S-1-16-8192)")
	if idx := strings.Index(integrity, " ("); idx > 0 {
		integrity = integrity[:idx]
	}

	// Get session ID
	session := getTokenSessionID(token)

	return user, integrity, session, nil
}

// getTokenSessionID returns the session ID from a token
func getTokenSessionID(token windows.Token) uint32 {
	var sessionID uint32
	var returnLength uint32
	err := windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&sessionID)), 4, &returnLength)
	if err != nil {
		return 0
	}
	return sessionID
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func integrityRank(level string) int {
	switch level {
	case "System":
		return 4
	case "High":
		return 3
	case "Medium":
		return 2
	case "Low":
		return 1
	default:
		return 0
	}
}
