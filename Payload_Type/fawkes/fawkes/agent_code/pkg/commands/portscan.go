package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"fawkes/pkg/structs"
)

type PortScanCommand struct{}

func (c *PortScanCommand) Name() string {
	return "port-scan"
}

func (c *PortScanCommand) Description() string {
	return "TCP connect scan for network service discovery"
}

type portScanArgs struct {
	Hosts       string `json:"hosts"`
	Ports       string `json:"ports"`
	Timeout     int    `json:"timeout"`
	Concurrency int    `json:"concurrency"`
}

type scanResult struct {
	Host string
	Port int
}

func (c *PortScanCommand) Execute(task structs.Task) structs.CommandResult {
	var args portScanArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: hosts parameter is required",
			Status:    "error",
			Completed: true,
		}
	}

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

	if args.Ports == "" {
		args.Ports = "21,22,23,25,53,80,88,110,135,139,143,389,443,445,993,995,1433,1521,3306,3389,5432,5900,5985,8080,8443"
	}

	if args.Timeout <= 0 {
		args.Timeout = 2
	}

	if args.Concurrency <= 0 {
		args.Concurrency = 100
	}

	// Parse hosts
	hosts, err := parseHosts(args.Hosts)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing hosts: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Parse ports
	ports, err := parsePorts(args.Ports)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing ports: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(hosts) == 0 || len(ports) == 0 {
		return structs.CommandResult{
			Output:    "Error: no valid hosts or ports to scan",
			Status:    "error",
			Completed: true,
		}
	}

	timeout := time.Duration(args.Timeout) * time.Second
	totalScans := len(hosts) * len(ports)

	// Run the scan
	var results []scanResult
	var mu sync.Mutex
	sem := make(chan struct{}, args.Concurrency)
	var wg sync.WaitGroup

	for _, host := range hosts {
		for _, port := range ports {
			wg.Add(1)
			sem <- struct{}{} // Acquire semaphore
			go func(h string, p int) {
				defer wg.Done()
				defer func() { <-sem }() // Release semaphore

				addr := fmt.Sprintf("%s:%d", h, p)
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err == nil {
					conn.Close()
					mu.Lock()
					results = append(results, scanResult{Host: h, Port: p})
					mu.Unlock()
				}
			}(host, port)
		}
	}

	wg.Wait()

	// Sort results by host then port
	sort.Slice(results, func(i, j int) bool {
		if results[i].Host != results[j].Host {
			return results[i].Host < results[j].Host
		}
		return results[i].Port < results[j].Port
	})

	// Format output
	var lines []string
	lines = append(lines, fmt.Sprintf("Scanned %d ports across %d hosts (%d total probes)",
		len(ports), len(hosts), totalScans))
	lines = append(lines, fmt.Sprintf("Found %d open ports", len(results)))
	lines = append(lines, "")

	if len(results) > 0 {
		lines = append(lines, fmt.Sprintf("%-20s %-8s %s", "Host", "Port", "Service"))
		lines = append(lines, strings.Repeat("-", 50))
		for _, r := range results {
			svc := knownService(r.Port)
			lines = append(lines, fmt.Sprintf("%-20s %-8d %s", r.Host, r.Port, svc))
		}
	}

	return structs.CommandResult{
		Output:    strings.Join(lines, "\n"),
		Status:    "success",
		Completed: true,
	}
}

// parseHosts parses a comma-separated list of IPs and CIDR ranges
func parseHosts(input string) ([]string, error) {
	var hosts []string
	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "/") {
			// CIDR notation
			ip, ipNet, err := net.ParseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR: %s", part)
			}
			for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
				// Skip network and broadcast addresses for /24 and smaller
				ones, bits := ipNet.Mask.Size()
				if ones < bits {
					if ip.Equal(ip.Mask(ipNet.Mask)) || isBroadcast(ip, ipNet) {
						continue
					}
				}
				hosts = append(hosts, ip.String())
				if len(hosts) > 1024 {
					return nil, fmt.Errorf("CIDR range too large (max 1024 hosts)")
				}
			}
		} else if strings.Contains(part, "-") {
			// Range like 192.168.1.1-10
			dashIdx := strings.LastIndex(part, "-")
			baseIP := part[:dashIdx]
			endStr := part[dashIdx+1:]

			// Check if it's a full IP range (192.168.1.1-192.168.1.10) or shorthand (192.168.1.1-10)
			endNum, err := strconv.Atoi(endStr)
			if err != nil {
				// Try as full IP
				return nil, fmt.Errorf("invalid range: %s", part)
			}

			ip := net.ParseIP(baseIP)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP: %s", baseIP)
			}
			ip4 := ip.To4()
			if ip4 == nil {
				return nil, fmt.Errorf("IPv4 only for ranges: %s", baseIP)
			}

			startOctet := int(ip4[3])
			if endNum < startOctet || endNum > 255 {
				return nil, fmt.Errorf("invalid range end: %d", endNum)
			}

			for i := startOctet; i <= endNum; i++ {
				hosts = append(hosts, fmt.Sprintf("%d.%d.%d.%d", ip4[0], ip4[1], ip4[2], i))
				if len(hosts) > 1024 {
					return nil, fmt.Errorf("range too large (max 1024 hosts)")
				}
			}
		} else {
			// Single IP
			ip := net.ParseIP(part)
			if ip == nil {
				// Try as hostname
				hosts = append(hosts, part)
			} else {
				hosts = append(hosts, ip.String())
			}
		}
	}
	return hosts, nil
}

// parsePorts parses a comma-separated list of ports and ranges
func parsePorts(input string) ([]int, error) {
	portSet := make(map[int]bool)
	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			// Port range
			rangeParts := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[1])
			}
			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}
			if end-start > 10000 {
				return nil, fmt.Errorf("port range too large (max 10000): %d-%d", start, end)
			}
			for p := start; p <= end; p++ {
				portSet[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of range: %d", p)
			}
			portSet[p] = true
		}
	}

	var ports []int
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	for i := range ip {
		if ip[i] != ipNet.IP[i]|^ipNet.Mask[i] {
			return false
		}
	}
	return true
}

func knownService(port int) string {
	services := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
		53: "DNS", 80: "HTTP", 88: "Kerberos", 110: "POP3",
		111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
		389: "LDAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
		995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
		3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
		5986: "WinRM-S", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
		9200: "Elastic", 27017: "MongoDB",
	}
	if svc, ok := services[port]; ok {
		return svc
	}
	return ""
}
