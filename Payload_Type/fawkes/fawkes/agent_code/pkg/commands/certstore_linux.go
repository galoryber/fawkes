//go:build linux

package commands

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type CertstoreCommand struct{}

func (c *CertstoreCommand) Name() string { return "certstore" }
func (c *CertstoreCommand) Description() string {
	return "Enumerate Linux certificate stores: /etc/ssl/certs, /etc/pki/tls/certs, NSS database"
}

type certstoreParamsLinux struct {
	Action   string `json:"action"`
	Store    string `json:"store"`
	Filter   string `json:"filter"`
	Format   string `json:"format"`
	Password string `json:"password"`
	Data     string `json:"data"`
}

func (c *CertstoreCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := requireParams[certstoreParamsLinux](task)
	if parseErr != nil {
		return *parseErr
	}
	if params.Action == "" {
		params.Action = "list"
	}

	switch params.Action {
	case "list", "find":
		return certstoreListLinux(params.Store, params.Filter)
	case "export":
		return certstoreExportLinux(params.Filter)
	case "delete", "import":
		return errorf("Action '%s' requires root permissions and is not supported via agent", params.Action)
	default:
		return errorf("Unknown action: %s (use 'list', 'find', 'export')", params.Action)
	}
}

// certstoreListLinux enumerates certificates from system certificate directories.
func certstoreListLinux(store, filter string) structs.CommandResult {
	// Certificate directories to search
	certDirs := []struct {
		path  string
		label string
	}{
		{"/etc/ssl/certs", "system-ssl"},
		{"/etc/pki/tls/certs", "pki-tls"},
		{"/usr/local/share/ca-certificates", "local-ca"},
		{"/usr/share/ca-certificates", "ca-certificates"},
	}

	// Filter directories by store parameter
	if store != "" {
		filtered := certDirs[:0]
		for _, d := range certDirs {
			if strings.EqualFold(d.label, store) || strings.Contains(d.path, store) {
				filtered = append(filtered, d)
			}
		}
		if len(filtered) > 0 {
			certDirs = filtered
		}
	}

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
		Path         string `json:"path,omitempty"`
	}

	var entries []certEntry
	now := time.Now()
	filterLower := strings.ToLower(filter)
	seen := make(map[string]bool)

	for _, dir := range certDirs {
		if _, err := os.Stat(dir.path); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(dir.path, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			// Only process .pem, .crt, .cer files
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".pem" && ext != ".crt" && ext != ".cer" {
				return nil
			}
			// Skip symlinks to avoid duplicates
			if info.Mode()&os.ModeSymlink != 0 {
				return nil
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			rest := data
			for {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}
				if block.Type != "CERTIFICATE" {
					continue
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					continue
				}

				thumbprint := fmt.Sprintf("%X", sha1.Sum(cert.Raw))
				if seen[thumbprint] {
					continue
				}
				seen[thumbprint] = true

				subject := cert.Subject.String()
				issuer := cert.Issuer.String()
				serial := fmt.Sprintf("%X", cert.SerialNumber)

				// Apply filter
				if filter != "" {
					searchStr := strings.ToLower(subject + issuer + serial + thumbprint)
					if !strings.Contains(searchStr, filterLower) {
						continue
					}
				}

				entries = append(entries, certEntry{
					Subject:      subject,
					Issuer:       issuer,
					SerialNumber: serial,
					NotBefore:    cert.NotBefore.Format("2006-01-02"),
					NotAfter:     cert.NotAfter.Format("2006-01-02"),
					Expired:      now.After(cert.NotAfter),
					Thumbprint:   thumbprint,
					Store:        dir.label,
					Path:         path,
				})
			}
			return nil
		})
	}

	// Also check user NSS database
	home, _ := os.UserHomeDir()
	nssDB := filepath.Join(home, ".pki", "nssdb")
	if _, err := os.Stat(nssDB); err == nil {
		// NSS database exists — note it but don't parse (requires certutil)
		entries = append(entries, certEntry{
			Subject: fmt.Sprintf("NSS Database at %s (use certutil -L -d sql:%s to list)", nssDB, nssDB),
			Store:   "nss-user",
			Path:    nssDB,
		})
	}

	jsonBytes, _ := json.Marshal(entries)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Linux Certificate Store (%d certificates) ===\n\n", len(entries)))
	for _, e := range entries {
		expiredFlag := ""
		if e.Expired {
			expiredFlag = " [EXPIRED]"
		}
		sb.WriteString(fmt.Sprintf("Subject: %s\n  Issuer: %s\n  Valid: %s to %s%s\n  Thumbprint: %s\n  Store: %s (%s)\n\n",
			e.Subject, e.Issuer, e.NotBefore, e.NotAfter, expiredFlag,
			e.Thumbprint, e.Store, e.Path))
	}

	return structs.CommandResult{
		Output: sb.String() + "\n" + string(jsonBytes),
		Status: "success",
	}
}

// certstoreExportLinux exports a certificate matching the filter as PEM.
func certstoreExportLinux(filter string) structs.CommandResult {
	if filter == "" {
		return errorResult("filter is required for export (use thumbprint or subject name)")
	}

	filterLower := strings.ToLower(filter)
	certDirs := []string{"/etc/ssl/certs", "/etc/pki/tls/certs", "/usr/local/share/ca-certificates"}

	for _, dir := range certDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		var foundPEM string
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || foundPEM != "" {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".pem" && ext != ".crt" && ext != ".cer" {
				return nil
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			rest := data
			for {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}
				if block.Type != "CERTIFICATE" {
					continue
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					continue
				}

				thumbprint := fmt.Sprintf("%X", sha1.Sum(cert.Raw))
				subject := cert.Subject.String()
				searchStr := strings.ToLower(subject + thumbprint)
				if strings.Contains(searchStr, filterLower) {
					foundPEM = string(pem.EncodeToMemory(block))
					return nil
				}
			}
			return nil
		})

		if foundPEM != "" {
			return successResult(fmt.Sprintf("=== Exported Certificate (PEM) ===\nFilter: %s\n\n%s", filter, foundPEM))
		}
	}

	return errorResult("No certificate found matching filter: " + filter)
}
