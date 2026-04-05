//go:build !windows

package commands

import (
	"fmt"
	"net"
	"time"
)

// dialNamedPipe is not supported on non-Windows platforms.
// Named pipes over SMB are a Windows-specific IPC mechanism.
func dialNamedPipe(_, _ string, _ time.Duration) (net.Conn, error) {
	return nil, fmt.Errorf("named pipe connections are only supported on Windows")
}
