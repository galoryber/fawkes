package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"fawkes/pkg/structs"
)

// PingCommand implements TCP connect-based host reachability checks with sweep support
type PingCommand struct{}

func (c *PingCommand) Name() string        { return "ping" }
func (c *PingCommand) Description() string { return "TCP connect host reachability check with subnet sweep support (T1018)" }

type pingArgs struct {
	Hosts   string `json:"hosts"`   // Single host, comma-separated, or CIDR (e.g., "192.168.1.0/24")
	Port    int    `json:"port"`    // Port to connect to (default: 445)
	Timeout int    `json:"timeout"` // Timeout per host in ms (default: 1000)
	Threads int    `json:"threads"` // Concurrent connections (default: 25)
}

type pingResult struct {
	Host    string
	Port    int
	Alive   bool
	Latency time.Duration
	Error   string
}

func (c *PingCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -hosts <IP/CIDR/range> [-port 445] [-timeout 1000] [-threads 25]",
			Status:    "error",
			Completed: true,
		}
	}

	var args pingArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Hosts == "" {
		return structs.CommandResult{
			Output:    "Error: hosts parameter is required",
			Status:    "error",
			Completed: true,
		}
	}
	if args.Port == 0 {
		args.Port = 445
	}
	if args.Timeout == 0 {
		args.Timeout = 1000
	}
	if args.Threads == 0 {
		args.Threads = 25
	}
	if args.Threads > 100 {
		args.Threads = 100
	}

	// Expand hosts to individual IPs
	targets := expandHosts(args.Hosts)
	if len(targets) == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: no valid hosts from '%s'", args.Hosts),
			Status:    "error",
			Completed: true,
		}
	}

	// Cap at 65536 hosts to prevent memory issues
	if len(targets) > 65536 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: too many hosts (%d). Max 65536. Use a smaller range.", len(targets)),
			Status:    "error",
			Completed: true,
		}
	}

	timeout := time.Duration(args.Timeout) * time.Millisecond
	results := make([]pingResult, len(targets))

	// Worker pool
	var wg sync.WaitGroup
	sem := make(chan struct{}, args.Threads)

	for i, host := range targets {
		if task.DidStop() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, h string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = tcpPing(h, args.Port, timeout)
		}(i, host)
	}
	wg.Wait()

	// Format output
	var sb strings.Builder
	alive := 0
	dead := 0

	sb.WriteString(fmt.Sprintf("[*] TCP ping sweep — %d hosts, port %d, timeout %dms, %d threads\n\n",
		len(targets), args.Port, args.Timeout, args.Threads))
	sb.WriteString(fmt.Sprintf("%-20s %-8s %-12s %s\n", "HOST", "PORT", "STATUS", "LATENCY"))
	sb.WriteString(strings.Repeat("-", 55) + "\n")

	for _, r := range results {
		if r.Alive {
			alive++
			sb.WriteString(fmt.Sprintf("%-20s %-8d %-12s %s\n",
				r.Host, r.Port, "OPEN", r.Latency.Round(time.Microsecond)))
		} else {
			dead++
		}
	}

	sb.WriteString(fmt.Sprintf("\n[*] Results: %d/%d hosts alive (port %d open)", alive, len(targets), args.Port))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func tcpPing(host string, port int, timeout time.Duration) pingResult {
	addr := fmt.Sprintf("%s:%d", host, port)
	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, timeout)
	latency := time.Since(start)

	if err != nil {
		return pingResult{Host: host, Port: port, Alive: false, Latency: latency, Error: err.Error()}
	}
	conn.Close()
	return pingResult{Host: host, Port: port, Alive: true, Latency: latency}
}

// expandHosts expands a host specification into individual IPs.
// Supports: single IP, comma-separated, CIDR notation, dash ranges (192.168.1.1-254)
func expandHosts(spec string) []string {
	var all []string
	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// CIDR notation
		if strings.Contains(part, "/") {
			all = append(all, expandCIDR(part)...)
			continue
		}

		// Dash range in last octet: 192.168.1.1-254
		if strings.Contains(part, "-") {
			all = append(all, expandDashRange(part)...)
			continue
		}

		// Single host
		all = append(all, part)
	}
	return all
}

func expandCIDR(cidr string) []string {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	var ips []string
	for ip := ip.Mask(network.Mask); network.Contains(ip); pingIncIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for /24 and smaller
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips
}

func expandDashRange(spec string) []string {
	// Parse "192.168.1.1-254" format
	lastDot := strings.LastIndex(spec, ".")
	if lastDot < 0 {
		return []string{spec}
	}

	prefix := spec[:lastDot+1]
	rangePart := spec[lastDot+1:]
	dashIdx := strings.Index(rangePart, "-")
	if dashIdx < 0 {
		return []string{spec}
	}

	var startNum, endNum int
	if _, err := fmt.Sscanf(rangePart[:dashIdx], "%d", &startNum); err != nil {
		return []string{spec}
	}
	if _, err := fmt.Sscanf(rangePart[dashIdx+1:], "%d", &endNum); err != nil {
		return []string{spec}
	}

	if startNum > endNum || startNum < 0 || endNum > 255 {
		return nil
	}

	var ips []string
	for i := startNum; i <= endNum; i++ {
		ips = append(ips, fmt.Sprintf("%s%d", prefix, i))
	}
	return ips
}

func pingIncIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
