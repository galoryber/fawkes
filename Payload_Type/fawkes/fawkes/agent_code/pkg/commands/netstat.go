package commands

import (
	"fmt"
	"sort"
	"strings"

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
			Output:    "No active connections found",
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

	// Format header
	var lines []string
	lines = append(lines, fmt.Sprintf("%-6s %-25s %-25s %-15s %s",
		"Proto", "Local Address", "Remote Address", "State", "PID"))
	lines = append(lines, strings.Repeat("-", 80))

	for _, conn := range conns {
		proto := protoName(conn.Type)
		local := formatAddr(conn.Laddr.IP, conn.Laddr.Port)
		remote := formatAddr(conn.Raddr.IP, conn.Raddr.Port)
		state := conn.Status
		if state == "" {
			state = "-"
		}

		pidStr := "-"
		if conn.Pid > 0 {
			pidStr = fmt.Sprintf("%d", conn.Pid)
		}

		lines = append(lines, fmt.Sprintf("%-6s %-25s %-25s %-15s %s",
			proto, local, remote, state, pidStr))
	}

	output := fmt.Sprintf("%d connections\n\n%s", len(conns), strings.Join(lines, "\n"))

	return structs.CommandResult{
		Output:    output,
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
