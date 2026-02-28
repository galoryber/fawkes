package commands

import (
	"encoding/json"
	"fmt"
	"sort"

	"fawkes/pkg/structs"

	psnet "github.com/shirou/gopsutil/v3/net"
)

type NetstatCommand struct{}

func (c *NetstatCommand) Name() string {
	return "net-stat"
}

func (c *NetstatCommand) Description() string {
	return "List active network connections and listening ports"
}

// netstatEntry represents a single network connection for JSON output.
type netstatEntry struct {
	Proto   string `json:"proto"`
	LocalIP string `json:"local_ip"`
	LocalPort uint32 `json:"local_port"`
	RemoteIP  string `json:"remote_ip"`
	RemotePort uint32 `json:"remote_port"`
	State   string `json:"state"`
	PID     int32  `json:"pid"`
}

func (c *NetstatCommand) Execute(task structs.Task) structs.CommandResult {
	// Get all connections (TCP and UDP)
	conns, err := psnet.Connections("all")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating connections: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(conns) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	// Sort: LISTEN first, then ESTABLISHED, then by local port
	sort.Slice(conns, func(i, j int) bool {
		si := statusPriority(conns[i].Status)
		sj := statusPriority(conns[j].Status)
		if si != sj {
			return si < sj
		}
		return conns[i].Laddr.Port < conns[j].Laddr.Port
	})

	entries := make([]netstatEntry, len(conns))
	for i, conn := range conns {
		state := conn.Status
		if state == "" {
			state = "-"
		}
		localIP := conn.Laddr.IP
		if localIP == "" {
			localIP = "*"
		}
		remoteIP := conn.Raddr.IP
		if remoteIP == "" {
			remoteIP = "*"
		}
		entries[i] = netstatEntry{
			Proto:      protoName(conn.Type),
			LocalIP:    localIP,
			LocalPort:  conn.Laddr.Port,
			RemoteIP:   remoteIP,
			RemotePort: conn.Raddr.Port,
			State:      state,
			PID:        conn.Pid,
		}
	}

	jsonBytes, err := json.Marshal(entries)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshalling connections: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(jsonBytes),
		Status:    "success",
		Completed: true,
	}
}

func formatAddr(ip string, port uint32) string {
	if ip == "" {
		ip = "*"
	}
	if port == 0 {
		return fmt.Sprintf("%s:*", ip)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func protoName(connType uint32) string {
	switch connType {
	case 1:
		return "TCP"
	case 2:
		return "UDP"
	default:
		return fmt.Sprintf("%d", connType)
	}
}

func statusPriority(status string) int {
	switch status {
	case "LISTEN":
		return 0
	case "ESTABLISHED":
		return 1
	case "TIME_WAIT":
		return 3
	case "CLOSE_WAIT":
		return 4
	default:
		return 2
	}
}
