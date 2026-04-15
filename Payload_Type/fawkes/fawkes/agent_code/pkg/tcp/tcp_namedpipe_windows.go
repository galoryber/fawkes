//go:build windows

package tcp

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

// createNamedPipeListener creates a Windows named pipe listener.
// The pipe is accessible locally as \\.\pipe\<pipeName> and remotely via SMB as \\<host>\pipe\<pipeName>.
// Uses a permissive security descriptor so any authenticated user can connect (operator controls access).
func createNamedPipeListener(pipeName string) (net.Listener, error) {
	path := `\\.\pipe\` + pipeName
	cfg := &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;WD)", // Allow Everyone full access
		MessageMode:        false,              // Byte-stream mode (same as TCP)
		InputBufferSize:    65536,
		OutputBufferSize:   65536,
	}
	listener, err := winio.ListenPipe(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create named pipe %s: %w", path, err)
	}
	return listener, nil
}
