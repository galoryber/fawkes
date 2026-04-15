//go:build !windows

package commands

import (
	"encoding/hex"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// darwinHashEntry represents a parsed macOS user hash.
type darwinHashEntry struct {
	Username   string `json:"username"`
	UID        string `json:"uid,omitempty"`
	GID        string `json:"gid,omitempty"`
	Home       string `json:"home,omitempty"`
	Shell      string `json:"shell,omitempty"`
	HashType   string `json:"hash_type"`
	Iterations int64  `json:"iterations,omitempty"`
	Salt       string `json:"salt,omitempty"`
	Entropy    string `json:"entropy,omitempty"`
}

// parseDarwinUserPlist extracts hash data from a user's binary plist.
func parseDarwinUserPlist(username string, data []byte) (*darwinHashEntry, error) {
	root, err := parseBplist(data)
	if err != nil {
		return nil, fmt.Errorf("parsing plist for %s: %w", username, err)
	}

	if root.kind != 'm' {
		return nil, fmt.Errorf("expected dict root, got %c", root.kind)
	}

	entry := &darwinHashEntry{
		Username: username,
	}

	// Extract user metadata
	if uid, ok := root.dictVal["uid"]; ok {
		entry.UID = bplistFirstString(uid)
	}
	if gid, ok := root.dictVal["gid"]; ok {
		entry.GID = bplistFirstString(gid)
	}
	if home, ok := root.dictVal["home"]; ok {
		entry.Home = bplistFirstString(home)
	}
	if shell, ok := root.dictVal["shell"]; ok {
		entry.Shell = bplistFirstString(shell)
	}

	// Extract ShadowHashData
	shadowHash, ok := root.dictVal["ShadowHashData"]
	if !ok {
		return nil, nil // No password hash
	}

	// ShadowHashData is an array containing one data element
	var hashBlob []byte
	if shadowHash.kind == 'a' && len(shadowHash.arrayVal) > 0 {
		if shadowHash.arrayVal[0].kind == 'd' {
			hashBlob = shadowHash.arrayVal[0].dataVal
		}
	} else if shadowHash.kind == 'd' {
		hashBlob = shadowHash.dataVal
	}

	if len(hashBlob) == 0 {
		return nil, nil
	}
	defer structs.ZeroBytes(hashBlob) // opsec: clear raw hash data

	return parseShadowHashData(entry, hashBlob)
}

// parseShadowHashData parses the inner plist containing hash algorithms.
func parseShadowHashData(entry *darwinHashEntry, blob []byte) (*darwinHashEntry, error) {
	inner, err := parseBplist(blob)
	if err != nil {
		return nil, fmt.Errorf("parsing ShadowHashData: %w", err)
	}

	if inner.kind != 'm' {
		return nil, fmt.Errorf("expected dict in ShadowHashData, got %c", inner.kind)
	}

	// Try SALTED-SHA512-PBKDF2 first (macOS 10.8+)
	if pbkdf2, ok := inner.dictVal["SALTED-SHA512-PBKDF2"]; ok && pbkdf2.kind == 'm' {
		entry.HashType = "SALTED-SHA512-PBKDF2"
		if iter, ok := pbkdf2.dictVal["iterations"]; ok && iter.kind == 'i' {
			entry.Iterations = iter.intVal
		}
		if salt, ok := pbkdf2.dictVal["salt"]; ok && salt.kind == 'd' {
			entry.Salt = hex.EncodeToString(salt.dataVal)
		}
		if entropy, ok := pbkdf2.dictVal["entropy"]; ok && entropy.kind == 'd' {
			entry.Entropy = hex.EncodeToString(entropy.dataVal)
		}
		return entry, nil
	}

	// Try SRP-RFC5054-4096-SHA512-PBKDF2 (macOS 10.14+)
	if srp, ok := inner.dictVal["SRP-RFC5054-4096-SHA512-PBKDF2"]; ok && srp.kind == 'm' {
		entry.HashType = "SRP-RFC5054-4096-SHA512-PBKDF2"
		if iter, ok := srp.dictVal["iterations"]; ok && iter.kind == 'i' {
			entry.Iterations = iter.intVal
		}
		if salt, ok := srp.dictVal["salt"]; ok && salt.kind == 'd' {
			entry.Salt = hex.EncodeToString(salt.dataVal)
		}
		if entropy, ok := srp.dictVal["entropy"]; ok && entropy.kind == 'd' {
			entry.Entropy = hex.EncodeToString(entropy.dataVal)
		}
		return entry, nil
	}

	// Try SALTED-SHA512 (macOS 10.7)
	if sha512, ok := inner.dictVal["SALTED-SHA512"]; ok && sha512.kind == 'd' {
		entry.HashType = "SALTED-SHA512"
		if len(sha512.dataVal) >= 4 {
			entry.Salt = hex.EncodeToString(sha512.dataVal[:4])
			entry.Entropy = hex.EncodeToString(sha512.dataVal[4:])
		}
		return entry, nil
	}

	// Unknown format
	var keys []string
	for k := range inner.dictVal {
		keys = append(keys, k)
	}
	entry.HashType = fmt.Sprintf("unknown (%s)", strings.Join(keys, ", "))
	return entry, nil
}

// formatDarwinHash formats a hash entry in hashcat-compatible format.
func formatDarwinHash(e darwinHashEntry) string {
	switch e.HashType {
	case "SALTED-SHA512-PBKDF2":
		return fmt.Sprintf("$ml$%d$%s$%s", e.Iterations, e.Salt, e.Entropy)
	case "SALTED-SHA512":
		return fmt.Sprintf("$LION$%s%s", e.Salt, e.Entropy)
	default:
		if e.Salt != "" && e.Entropy != "" {
			return fmt.Sprintf("$%s$%d$%s$%s", e.HashType, e.Iterations, e.Salt, e.Entropy)
		}
		return e.HashType
	}
}

// bplistFirstString extracts the first string from a bplist value.
func bplistFirstString(v bplistValue) string {
	if v.kind == 's' {
		return v.strVal
	}
	if v.kind == 'i' {
		return fmt.Sprintf("%d", v.intVal)
	}
	if v.kind == 'a' && len(v.arrayVal) > 0 {
		return bplistFirstString(v.arrayVal[0])
	}
	return ""
}

// isSystemAccount returns true for macOS system/daemon accounts.
func isSystemAccount(username string) bool {
	// System accounts start with _ on macOS
	if strings.HasPrefix(username, "_") {
		return true
	}
	switch username {
	case "daemon", "nobody":
		return true
	}
	return false
}
