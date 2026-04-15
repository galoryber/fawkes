//go:build windows

package commands

import (
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

// dialNamedPipe connects to a remote named pipe over SMB (port 445) and returns a net.Conn.
// The pipe path is constructed as \\<host>\pipe\<pipeName>.
// For local connections, host can be "." (e.g., \\.\pipe\myPipe).
func dialNamedPipe(host, pipeName string, timeout time.Duration) (net.Conn, error) {
	path := fmt.Sprintf(`\\%s\pipe\%s`, host, pipeName)
	return winio.DialPipe(path, &timeout)
}
