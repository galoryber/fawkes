package commands

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"fawkes/pkg/structs"

	"github.com/hirochachacha/go-smb2"
)

// smbDecodeHash decodes an NTLM hash from various formats:
// - Pure hex: "8846f7eaee8fb117ad06bdd830b7586c" (16 bytes = NT hash)
// - LM:NT format: "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
func smbDecodeHash(hashStr string) ([]byte, error) {
	hashStr = stripLMPrefix(hashStr)
	hashBytes, err := hex.DecodeString(hashStr)
	if err != nil {
		return nil, fmt.Errorf("hash must be hex-encoded: %v", err)
	}
	if len(hashBytes) != 16 {
		return nil, fmt.Errorf("NT hash must be 16 bytes (32 hex chars), got %d bytes", len(hashBytes))
	}
	return hashBytes, nil
}

// smbDialSession establishes an authenticated SMB session to a remote host.
// It handles TCP connection, NTLM authentication (password or pass-the-hash),
// deadline management, and OPSEC hash zeroing.
// Callers must close both the session (Logoff) and conn (Close) when done.
func smbDialSession(host string, port int, username, domain, password, hash string, timeout time.Duration) (*smb2.Session, net.Conn, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("TCP connect to %s:%d: %v", host, port, err)
	}

	initiator := &smb2.NTLMInitiator{
		User:   username,
		Domain: domain,
	}
	if hash != "" {
		hashBytes, err := smbDecodeHash(hash)
		if err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("invalid NTLM hash: %v", err)
		}
		initiator.Hash = hashBytes
	} else {
		initiator.Password = password
	}

	d := &smb2.Dialer{Initiator: initiator}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	session, err := d.Dial(conn)
	structs.ZeroBytes(initiator.Hash)
	_ = conn.SetDeadline(time.Time{}) // Clear deadline after auth
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}

	return session, conn, nil
}
