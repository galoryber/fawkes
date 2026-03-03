package commands

// cloudmetadata_helpers.go contains pure helper functions extracted from
// cloudmetadata.go for cross-platform testing without cloud access.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// normalizeProvider validates and normalizes a cloud provider name.
// Returns the normalized name or empty string if invalid.
func normalizeProvider(provider string) string {
	p := strings.ToLower(provider)
	switch p {
	case "aws", "azure", "gcp", "digitalocean":
		return p
	default:
		return ""
	}
}

// formatAWSCredsJSON parses AWS IAM credential JSON and formats it for display.
func formatAWSCredsJSON(jsonStr string) string {
	var sb strings.Builder
	var credMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &credMap); err != nil {
		return fmt.Sprintf("    Raw: %s\n", truncate(jsonStr, 200))
	}
	if ak, ok := credMap["AccessKeyId"].(string); ok {
		sb.WriteString(fmt.Sprintf("    AccessKeyId:     %s\n", ak))
	}
	if sk, ok := credMap["SecretAccessKey"].(string); ok {
		sb.WriteString(fmt.Sprintf("    SecretAccessKey: %s\n", sk))
	}
	if tok, ok := credMap["Token"].(string); ok {
		sb.WriteString(fmt.Sprintf("    Token:           %s...\n", truncate(tok, 40)))
	}
	if exp, ok := credMap["Expiration"].(string); ok {
		sb.WriteString(fmt.Sprintf("    Expiration:      %s\n", exp))
	}
	return sb.String()
}

// formatAWSIdentityJSON parses an AWS instance identity document and formats it.
func formatAWSIdentityJSON(jsonStr string) string {
	var sb strings.Builder
	var idDoc map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &idDoc); err != nil {
		return fmt.Sprintf("    %s\n", jsonStr)
	}
	for _, key := range []string{"accountId", "instanceId", "instanceType", "region", "availabilityZone", "architecture", "imageId", "privateIp"} {
		if v, ok := idDoc[key]; ok {
			sb.WriteString(fmt.Sprintf("    %-20s %v\n", key+":", v))
		}
	}
	return sb.String()
}

// formatAzureInstanceJSON parses Azure instance metadata JSON and extracts compute fields.
func formatAzureInstanceJSON(jsonStr string) string {
	var sb strings.Builder
	var inst map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &inst); err != nil {
		return fmt.Sprintf("  %s\n", truncate(jsonStr, 2000))
	}
	compute, ok := inst["compute"].(map[string]interface{})
	if !ok {
		return ""
	}
	for _, key := range []string{"name", "vmId", "vmSize", "location", "resourceGroupName", "subscriptionId", "osType", "offer", "publisher", "sku", "version", "zone"} {
		if v, ok := compute[key]; ok && v != "" {
			sb.WriteString(fmt.Sprintf("  %-24s %v\n", key+":", v))
		}
	}
	if tags, ok := compute["tagsList"].([]interface{}); ok && len(tags) > 0 {
		sb.WriteString("  Tags:\n")
		for _, t := range tags {
			if tag, ok := t.(map[string]interface{}); ok {
				sb.WriteString(fmt.Sprintf("    %v = %v\n", tag["name"], tag["value"]))
			}
		}
	}
	return sb.String()
}

// formatAzureTokenJSON parses Azure managed identity token JSON and formats it.
func formatAzureTokenJSON(jsonStr string) string {
	var sb strings.Builder
	var token map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &token); err != nil {
		return fmt.Sprintf("[+] Azure Token (raw): %s\n", truncate(jsonStr, 200))
	}
	sb.WriteString("[+] Azure Managed Identity Token:\n")
	if at, ok := token["access_token"].(string); ok {
		sb.WriteString(fmt.Sprintf("    Access Token: %s...\n", truncate(at, 60)))
	}
	if rt, ok := token["resource"].(string); ok {
		sb.WriteString(fmt.Sprintf("    Resource:     %s\n", rt))
	}
	if exp, ok := token["expires_on"].(string); ok {
		sb.WriteString(fmt.Sprintf("    Expires On:   %s\n", exp))
	}
	return sb.String()
}

// formatAzureNetworkJSON parses Azure network metadata and formats interface info.
func formatAzureNetworkJSON(jsonStr string) string {
	var sb strings.Builder
	var inst map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &inst); err != nil {
		return ""
	}
	network, ok := inst["network"].(map[string]interface{})
	if !ok {
		return ""
	}
	ifaces, ok := network["interface"].([]interface{})
	if !ok {
		return ""
	}
	for i, iface := range ifaces {
		m, ok := iface.(map[string]interface{})
		if !ok {
			continue
		}
		sb.WriteString(fmt.Sprintf("  Interface %d:\n", i))
		if mac, ok := m["macAddress"].(string); ok {
			sb.WriteString(fmt.Sprintf("    MAC: %s\n", mac))
		}
		if ipv4, ok := m["ipv4"].(map[string]interface{}); ok {
			if addrs, ok := ipv4["ipAddress"].([]interface{}); ok {
				for _, a := range addrs {
					if addr, ok := a.(map[string]interface{}); ok {
						sb.WriteString(fmt.Sprintf("    Private: %v  Public: %v\n", addr["privateIpAddress"], addr["publicIpAddress"]))
					}
				}
			}
			if subnets, ok := ipv4["subnet"].([]interface{}); ok {
				for _, s := range subnets {
					if subnet, ok := s.(map[string]interface{}); ok {
						sb.WriteString(fmt.Sprintf("    Subnet: %v/%v\n", subnet["address"], subnet["prefix"]))
					}
				}
			}
		}
	}
	return sb.String()
}

// formatGCPTokenJSON parses a GCP service account token response and formats it.
func formatGCPTokenJSON(jsonStr string) string {
	var sb strings.Builder
	var token map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &token); err != nil {
		return ""
	}
	if at, ok := token["access_token"].(string); ok {
		sb.WriteString(fmt.Sprintf("    Access Token: %s...\n", truncate(at, 60)))
	}
	if exp, ok := token["expires_in"]; ok {
		sb.WriteString(fmt.Sprintf("    Expires In:   %v seconds\n", exp))
	}
	return sb.String()
}

// formatDOMetadataJSON parses DigitalOcean droplet metadata JSON and formats it.
func formatDOMetadataJSON(jsonStr string) string {
	var sb strings.Builder
	var doMeta map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &doMeta); err != nil {
		return truncate(jsonStr, 2000)
	}
	for _, key := range []string{"droplet_id", "hostname", "region", "vendor_data", "public_keys"} {
		if v, ok := doMeta[key]; ok {
			sb.WriteString(fmt.Sprintf("  %-18s %v\n", key+":", v))
		}
	}
	if ifaces, ok := doMeta["interfaces"].(map[string]interface{}); ok {
		for netType, nets := range ifaces {
			if netSlice, ok := nets.([]interface{}); ok {
				for _, n := range netSlice {
					if net, ok := n.(map[string]interface{}); ok {
						sb.WriteString(fmt.Sprintf("  %s: ip=%v mac=%v\n", netType, net["ipv4"], net["mac"]))
					}
				}
			}
		}
	}
	return sb.String()
}

// formatDONetworkJSON parses DigitalOcean network metadata and formats it.
func formatDONetworkJSON(jsonStr string) string {
	var sb strings.Builder
	var doMeta map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &doMeta); err != nil {
		return ""
	}
	ifaces, ok := doMeta["interfaces"].(map[string]interface{})
	if !ok {
		return ""
	}
	for netType, nets := range ifaces {
		netSlice, ok := nets.([]interface{})
		if !ok {
			continue
		}
		for _, n := range netSlice {
			net, ok := n.(map[string]interface{})
			if !ok {
				continue
			}
			sb.WriteString(fmt.Sprintf("  %s:\n", netType))
			if ipv4, ok := net["ipv4"].(map[string]interface{}); ok {
				sb.WriteString(fmt.Sprintf("    IPv4: %v  Netmask: %v  Gateway: %v\n",
					ipv4["ip_address"], ipv4["netmask"], ipv4["gateway"]))
			}
			if mac, ok := net["mac"].(string); ok {
				sb.WriteString(fmt.Sprintf("    MAC:  %s\n", mac))
			}
		}
	}
	return sb.String()
}
