package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// --- DigitalOcean ---

func doDumpAll(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== DigitalOcean Droplet Metadata ===\n")

	resp := metadataGet(doMetadataURL, timeout, nil)
	if resp == "" {
		sb.WriteString("[-] Could not retrieve DO metadata\n")
		return sb.String()
	}

	sb.WriteString(formatDOMetadataJSON(resp))

	sb.WriteString("\n")
	sb.WriteString(doGetUserdata(timeout))
	return sb.String()
}

func doGetIdentity(timeout time.Duration) string {
	var sb strings.Builder

	resp := metadataGet(doMetadataURL, timeout, nil)
	if resp == "" {
		sb.WriteString("[-] DigitalOcean: Could not retrieve identity\n")
		return sb.String()
	}

	var doMeta map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &doMeta); err == nil {
		sb.WriteString("[+] DigitalOcean Identity:\n")
		for _, key := range []string{"droplet_id", "hostname", "region"} {
			if v, ok := doMeta[key]; ok {
				sb.WriteString(fmt.Sprintf("    %-14s %v\n", key+":", v))
			}
		}
	}
	return sb.String()
}

func doGetUserdata(timeout time.Duration) string {
	var sb strings.Builder
	ud := metadataGet(doMetadataBase+"/metadata/v1/user-data", timeout, nil)
	if ud == "" {
		sb.WriteString("[*] DigitalOcean: No user-data configured\n")
	} else {
		sb.WriteString("[+] DigitalOcean User Data:\n")
		sb.WriteString(truncate(ud, 4096))
		sb.WriteString("\n")
	}
	return sb.String()
}

func doGetNetwork(timeout time.Duration) string {
	var sb strings.Builder

	resp := metadataGet(doMetadataURL, timeout, nil)
	if resp == "" {
		sb.WriteString("[-] DigitalOcean: Could not retrieve network info\n")
		return sb.String()
	}

	sb.WriteString("[+] DigitalOcean Network:\n")
	sb.WriteString(formatDONetworkJSON(resp))
	return sb.String()
}
