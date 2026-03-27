package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"fawkes/pkg/structs"

	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

type NetstatCommand struct{}

func (c *NetstatCommand) Name() string {
	return "net-stat"
}

func (c *NetstatCommand) Description() string {
	return "List active network connections and listening ports"
}

type netstatArgs struct {
	State string `json:"state"` // LISTEN, ESTABLISHED, TIME_WAIT, CLOSE_WAIT, etc.
	Proto string `json:"proto"` // tcp, udp
	Port  int    `json:"port"`  // filter by local or remote port
	PID   int32  `json:"pid"`   // filter by process ID
}

// netstatEntry represents a single network connection for JSON output.
type netstatEntry struct {
	Proto      string `json:"proto"`
	LocalIP    string `json:"local_ip"`
	LocalPort  uint32 `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort uint32 `json:"remote_port"`
	State      string `json:"state"`
	PID        int32  `json:"pid"`
	Process    string `json:"process,omitempty"`
}

func (c *NetstatCommand) Execute(task structs.Task) structs.CommandResult {
	var args netstatArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Invalid parameters: %v", err)
		}
	}

	// Get all connections (TCP and UDP)
	conns, err := psnet.Connections("all")
	if err != nil {
		return errorf("Error enumerating connections: %v", err)
	}

	// Apply filters
	var filtered []psnet.ConnectionStat
	for _, conn := range conns {
		if args.State != "" && !strings.EqualFold(conn.Status, args.State) {
			continue
		}
		if args.Proto != "" && !strings.EqualFold(protoName(conn.Type), args.Proto) {
			continue
		}
		if args.Port != 0 && conn.Laddr.Port != uint32(args.Port) && conn.Raddr.Port != uint32(args.Port) {
			continue
		}
		if args.PID != 0 && conn.Pid != args.PID {
			continue
		}
		filtered = append(filtered, conn)
	}

	if len(filtered) == 0 {
		return successResult("[]")
	}

	// Sort: LISTEN first, then ESTABLISHED, then by local port
	sort.Slice(filtered, func(i, j int) bool {
		si := statusPriority(filtered[i].Status)
		sj := statusPriority(filtered[j].Status)
		if si != sj {
			return si < sj
		}
		return filtered[i].Laddr.Port < filtered[j].Laddr.Port
	})

	// Build PID-to-process-name cache
	pidNames := resolveProcessNames(filtered)

	entries := make([]netstatEntry, len(filtered))
	for i, conn := range filtered {
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
			Process:    pidNames[conn.Pid],
		}
	}

	jsonBytes, err := json.Marshal(entries)
	if err != nil {
		return errorf("Error marshalling connections: %v", err)
	}

	return successResult(string(jsonBytes))
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

// resolveProcessNames builds a PID-to-process-name map for the given connections.
func resolveProcessNames(conns []psnet.ConnectionStat) map[int32]string {
	names := make(map[int32]string)
	for _, conn := range conns {
		if conn.Pid <= 0 {
			continue
		}
		if _, ok := names[conn.Pid]; ok {
			continue
		}
		if p, err := process.NewProcess(conn.Pid); err == nil {
			if name, err := p.Name(); err == nil {
				names[conn.Pid] = name
			}
		}
	}
	return names
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
