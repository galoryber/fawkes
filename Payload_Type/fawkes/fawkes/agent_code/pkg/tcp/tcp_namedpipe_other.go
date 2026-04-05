//go:build !windows

package tcp

import (
	"fmt"
	"net"
)

// createNamedPipeListener is not supported on non-Windows platforms.
func createNamedPipeListener(_ string) (net.Listener, error) {
	return nil, fmt.Errorf("named pipe P2P listener is only supported on Windows")
}
