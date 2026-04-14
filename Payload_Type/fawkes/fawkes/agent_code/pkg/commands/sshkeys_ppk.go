package commands

import (
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// ppkInfo holds parsed metadata from a PuTTY .ppk private key file.
type ppkInfo struct {
	path       string
	keyType    string
	encryption string
	comment    string
	version    int
}

// parsePPKHeader reads the header of a .ppk file to extract key metadata.
// Supports PuTTY-User-Key-File-2 and PuTTY-User-Key-File-3 formats.
func parsePPKHeader(path string) ppkInfo {
	content, err := os.ReadFile(path)
	if err != nil {
		return ppkInfo{}
	}
	defer structs.ZeroBytes(content)

	info := ppkInfo{path: path}
	lines := strings.SplitN(string(content), "\n", 10) // only need header lines

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PuTTY-User-Key-File-2:") {
			info.version = 2
			info.keyType = strings.TrimSpace(strings.TrimPrefix(line, "PuTTY-User-Key-File-2:"))
		} else if strings.HasPrefix(line, "PuTTY-User-Key-File-3:") {
			info.version = 3
			info.keyType = strings.TrimSpace(strings.TrimPrefix(line, "PuTTY-User-Key-File-3:"))
		} else if strings.HasPrefix(line, "Encryption:") {
			info.encryption = strings.TrimSpace(strings.TrimPrefix(line, "Encryption:"))
		} else if strings.HasPrefix(line, "Comment:") {
			info.comment = strings.TrimSpace(strings.TrimPrefix(line, "Comment:"))
		}
	}

	if info.keyType == "" {
		return ppkInfo{} // not a valid PPK file
	}
	if info.encryption == "" {
		info.encryption = "none"
	}

	return info
}

// decodePuTTYSessionName reverses PuTTY's URL-encoding of session names.
// PuTTY uses %XX encoding for special characters in registry key names.
func decodePuTTYSessionName(name string) string {
	var result strings.Builder
	i := 0
	for i < len(name) {
		if name[i] == '%' && i+2 < len(name) {
			hi := unhex(name[i+1])
			lo := unhex(name[i+2])
			if hi >= 0 && lo >= 0 {
				result.WriteByte(byte(hi<<4 | lo))
				i += 3
				continue
			}
		}
		result.WriteByte(name[i])
		i++
	}
	return result.String()
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

// listSSHKeysInDir returns names of SSH key files found in a directory.
func listSSHKeysInDir(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var keys []string
	keyPatterns := []string{"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa", "authorized_keys", "known_hosts", "config"}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		for _, pattern := range keyPatterns {
			if name == pattern || strings.HasSuffix(name, ".pub") || strings.HasSuffix(name, ".ppk") {
				keys = append(keys, name)
				break
			}
		}
	}
	return keys
}

// findPPKFilesInDirs searches a list of directories for .ppk files.
func findPPKFilesInDirs(searchDirs []string) []ppkInfo {
	var results []ppkInfo
	seen := make(map[string]bool)

	for _, dir := range searchDirs {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".ppk") {
				continue
			}
			fullPath := filepath.Join(dir, entry.Name())
			if seen[fullPath] {
				continue
			}
			seen[fullPath] = true

			if info := parsePPKHeader(fullPath); info.path != "" {
				results = append(results, info)
			}
		}
	}

	return results
}
