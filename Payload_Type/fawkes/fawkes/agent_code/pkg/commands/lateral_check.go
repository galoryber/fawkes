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

// LateralCheckCommand tests which lateral movement methods are available against targets.
type LateralCheckCommand struct{}

func (c *LateralCheckCommand) Name() string { return "lateral-check" }
func (c *LateralCheckCommand) Description() string {
	return "Test lateral movement options against targets"
}

type lateralCheckArgs struct {
	Hosts   string `json:"hosts"`   // single IP, comma-separated, or CIDR
	Timeout int    `json:"timeout"` // per-check timeout in seconds
}

type lateralTarget struct {
	Host    string
	Results map[string]lateralResult
}

type lateralResult struct {
	Available bool
	Detail    string
}

type lateralOutputEntry struct {
	Host      string   `json:"host"`
	Available []string `json:"available,omitempty"`
	Closed    []string `json:"closed,omitempty"`
	Suggested []string `json:"suggested,omitempty"`
	TotalOpen int      `json:"total_open"`
}

func (c *LateralCheckCommand) Execute(task structs.Task) structs.CommandResult {
	var args lateralCheckArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Hosts == "" {
		return structs.CommandResult{
			Output:    "Error: -hosts parameter required (IP, comma-separated IPs, or CIDR)",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Timeout <= 0 {
		args.Timeout = 3
	}
	timeout := time.Duration(args.Timeout) * time.Second

	// Parse hosts
	hosts := lateralParseHosts(args.Hosts)
	if len(hosts) == 0 {
		return structs.CommandResult{
			Output:    "Error: no valid hosts parsed from input",
			Status:    "error",
			Completed: true,
		}
	}

	if len(hosts) > 256 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: too many hosts (%d). Maximum 256.", len(hosts)),
			Status:    "error",
			Completed: true,
		}
	}

	// Check each host concurrently
	var mu sync.Mutex
	var wg sync.WaitGroup
	results := make([]lateralTarget, 0, len(hosts))
	sem := make(chan struct{}, 10) // limit concurrency

	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			if task.DidStop() {
				return
			}

			target := lateralTarget{
				Host:    h,
				Results: make(map[string]lateralResult),
			}

			// Check ports in parallel
			var portWg sync.WaitGroup
			var portMu sync.Mutex

			checks := []struct {
				name string
				port string
			}{
				{"SMB (445)", "445"},
				{"WinRM-HTTP (5985)", "5985"},
				{"WinRM-HTTPS (5986)", "5986"},
				{"RDP (3389)", "3389"},
				{"RPC (135)", "135"},
				{"SSH (22)", "22"},
				{"WMI-DCOM (135)", "135"},
			}

			// Deduplicate port checks
			portChecks := make(map[string][]string) // port -> []names
			for _, check := range checks {
				portChecks[check.port] = append(portChecks[check.port], check.name)
			}

			for port, names := range portChecks {
				portWg.Add(1)
				go func(p string, ns []string) {
					defer portWg.Done()
					conn, err := net.DialTimeout("tcp", net.JoinHostPort(h, p), timeout)
					available := err == nil
					detail := "port closed"
					if available {
						conn.Close()
						detail = "port open"
					} else if isTimeout(err) {
						detail = "timeout"
					}

					portMu.Lock()
					for _, n := range ns {
						target.Results[n] = lateralResult{
							Available: available,
							Detail:    detail,
						}
					}
					portMu.Unlock()
				}(port, names)
			}
			portWg.Wait()

			// If SMB is open, try to check admin access by connecting to IPC$
			if r, ok := target.Results["SMB (445)"]; ok && r.Available {
				target.Results["SMB (445)"] = lateralResult{
					Available: true,
					Detail:    "port open — use smb/psexec for lateral movement",
				}
			}

			mu.Lock()
			results = append(results, target)
			mu.Unlock()
		}(host)
	}
	wg.Wait()

	// Build JSON output
	var entries []lateralOutputEntry
	order := []string{"SMB (445)", "WinRM-HTTP (5985)", "WinRM-HTTPS (5986)", "RDP (3389)", "RPC (135)", "SSH (22)", "WMI-DCOM (135)"}

	for _, target := range results {
		entry := lateralOutputEntry{Host: target.Host}

		for _, name := range order {
			r, ok := target.Results[name]
			if !ok {
				continue
			}
			if r.Available {
				entry.Available = append(entry.Available, name)
				entry.TotalOpen++
			} else {
				entry.Closed = append(entry.Closed, name)
			}
		}

		// Suggest methods
		if r, ok := target.Results["SMB (445)"]; ok && r.Available {
			entry.Suggested = append(entry.Suggested, "psexec", "smb", "dcom")
		}
		if r, ok := target.Results["WinRM-HTTP (5985)"]; ok && r.Available {
			entry.Suggested = append(entry.Suggested, "winrm")
		}
		if r, ok := target.Results["WinRM-HTTPS (5986)"]; ok && r.Available {
			entry.Suggested = append(entry.Suggested, "winrm (HTTPS)")
		}
		if r, ok := target.Results["SSH (22)"]; ok && r.Available {
			entry.Suggested = append(entry.Suggested, "ssh")
		}
		if r, ok := target.Results["RPC (135)"]; ok && r.Available {
			entry.Suggested = append(entry.Suggested, "wmi")
		}

		entries = append(entries, entry)
	}

	if len(entries) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	data, _ := json.Marshal(entries)
	return structs.CommandResult{
		Output:    string(data),
		Status:    "success",
		Completed: true,
	}
}

// lateralParseHosts parses comma-separated IPs and CIDR ranges
func lateralParseHosts(input string) []string {
	var hosts []string
	seen := make(map[string]bool)

	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check if it's a CIDR
		if strings.Contains(part, "/") {
			_, ipNet, err := net.ParseCIDR(part)
			if err != nil {
				continue
			}
			for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); lateralIncIP(ip) {
				s := ip.String()
				if !seen[s] {
					hosts = append(hosts, s)
					seen[s] = true
				}
				if len(hosts) > 256 {
					return hosts
				}
			}
		} else {
			if !seen[part] {
				hosts = append(hosts, part)
				seen[part] = true
			}
		}
	}
	return hosts
}

func lateralIncIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}
