package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

func awsListBuckets(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== AWS S3 Bucket Enumeration ===\n\n")

	h := awsHeaders(timeout)
	roles := metadataGet(awsCredsURL, timeout, h)
	if roles == "" {
		sb.WriteString("[-] No IAM role attached — cannot enumerate S3 buckets\n")
		return sb.String()
	}

	role := strings.TrimSpace(strings.Split(roles, "\n")[0])
	credsJSON := metadataGet(awsCredsURL+role, timeout, h)
	if credsJSON == "" {
		sb.WriteString("[-] Could not retrieve IAM credentials\n")
		return sb.String()
	}
	defer structs.ZeroString(&credsJSON)

	var creds struct {
		AccessKeyId     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
	}
	if err := json.Unmarshal([]byte(credsJSON), &creds); err != nil {
		sb.WriteString("[-] Could not parse IAM credentials\n")
		return sb.String()
	}
	defer func() {
		structs.ZeroString(&creds.AccessKeyId)
		structs.ZeroString(&creds.SecretAccessKey)
		structs.ZeroString(&creds.Token)
	}()

	sb.WriteString(fmt.Sprintf("[+] IAM Role: %s\n\n", role))

	region := metadataGet(awsMetaURL+"placement/region", timeout, h)
	if region == "" {
		region = "us-east-1"
	}

	s3Endpoint := fmt.Sprintf("https://s3.%s.amazonaws.com/", region)
	resp := awsSignedGet(s3Endpoint, "Action=ListBuckets", creds.AccessKeyId, creds.SecretAccessKey, creds.Token, "s3", timeout)

	if resp == "" {
		resp = metadataGet("https://s3.amazonaws.com/", timeout, map[string]string{
			"X-Amz-Security-Token": creds.Token,
		})
	}

	if resp == "" {
		sb.WriteString("[-] S3 ListBuckets failed (no permissions or no buckets)\n")
		return sb.String()
	}

	bucketNames := cloudExtractXMLValues(resp, "Name")
	creationDates := cloudExtractXMLValues(resp, "CreationDate")

	if len(bucketNames) == 0 {
		sb.WriteString("[*] No S3 buckets found (or ListBuckets denied)\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("[+] Found %d bucket(s):\n\n", len(bucketNames)))

	for i, name := range bucketNames {
		created := ""
		if i < len(creationDates) {
			created = creationDates[i]
		}
		if created != "" {
			sb.WriteString(fmt.Sprintf("  s3://%s  (created: %s)\n", name, created))
		} else {
			sb.WriteString(fmt.Sprintf("  s3://%s\n", name))
		}

		bucketEndpoint := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/", name, region)
		listResp := awsSignedGet(bucketEndpoint, "list-type=2&max-keys=5", creds.AccessKeyId, creds.SecretAccessKey, creds.Token, "s3", timeout)
		if listResp != "" {
			keys := cloudExtractXMLValues(listResp, "Key")
			if len(keys) > 0 {
				sb.WriteString(fmt.Sprintf("    Sample objects (%d shown):\n", len(keys)))
				for _, key := range keys {
					sb.WriteString(fmt.Sprintf("      %s\n", key))
				}
			}
		}
	}

	return sb.String()
}

func azureListStorageContainers(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== Azure Blob Storage Enumeration ===\n\n")

	tokenURL := azureMetadataBase + "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"
	tokenResp := metadataGet(tokenURL, timeout, map[string]string{"Metadata": "true"})
	if tokenResp == "" {
		sb.WriteString("[-] No managed identity available or Storage scope denied\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenResp)

	var tokenData struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(tokenResp), &tokenData); err != nil {
		sb.WriteString("[-] Could not parse managed identity token\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenData.AccessToken)

	sb.WriteString("[+] Storage token acquired\n\n")

	authHeaders := map[string]string{
		"Authorization":  "Bearer " + tokenData.AccessToken,
		"x-ms-version":   "2021-08-06",
	}

	instanceResp := metadataGet(azureInstanceURL, timeout, map[string]string{"Metadata": "true"})
	var storageAccounts []string
	if instanceResp != "" {
		var inst struct {
			Compute struct {
				ResourceGroupName string `json:"resourceGroupName"`
				Tags              string `json:"tags"`
			} `json:"compute"`
		}
		if json.Unmarshal([]byte(instanceResp), &inst) == nil {
			for _, tag := range strings.Split(inst.Compute.Tags, ";") {
				parts := strings.SplitN(tag, ":", 2)
				if len(parts) == 2 {
					lower := strings.ToLower(parts[0])
					if strings.Contains(lower, "storage") || strings.Contains(lower, "blob") {
						storageAccounts = append(storageAccounts, strings.TrimSpace(parts[1]))
					}
				}
			}
			rg := inst.Compute.ResourceGroupName
			if rg != "" {
				clean := strings.ToLower(strings.ReplaceAll(rg, "-", ""))
				storageAccounts = append(storageAccounts, clean, clean+"storage", clean+"sa")
			}
		}
	}

	if len(storageAccounts) == 0 {
		sb.WriteString("[*] No storage account names discovered from instance metadata.\n")
		sb.WriteString("    Specify account name manually or check Azure resource tags.\n")
		return sb.String()
	}

	found := 0
	for _, account := range storageAccounts {
		listURL := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list", account)
		resp := metadataGet(listURL, timeout, authHeaders)
		if resp == "" || strings.Contains(resp, "<Error>") || strings.Contains(resp, "AuthenticationFailed") {
			continue
		}

		containerNames := cloudExtractXMLValues(resp, "Name")
		if len(containerNames) == 0 {
			continue
		}

		found++
		sb.WriteString(fmt.Sprintf("[+] Storage Account: %s — %d container(s)\n", account, len(containerNames)))

		for _, container := range containerNames {
			blobURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list&maxresults=5", account, container)
			blobResp := metadataGet(blobURL, timeout, authHeaders)
			blobCount := 0
			if blobResp != "" {
				blobNames := cloudExtractXMLValues(blobResp, "Name")
				blobCount = len(blobNames)
				if blobCount > 0 {
					sb.WriteString(fmt.Sprintf("  %s (%d sample blob(s)):\n", container, blobCount))
					for _, blob := range blobNames {
						sb.WriteString(fmt.Sprintf("    %s\n", blob))
					}
				} else {
					sb.WriteString(fmt.Sprintf("  %s (empty or list denied)\n", container))
				}
			} else {
				sb.WriteString(fmt.Sprintf("  %s (list denied)\n", container))
			}
		}
		sb.WriteString("\n")
	}

	if found == 0 {
		sb.WriteString("[*] No accessible storage accounts found among candidates: " + strings.Join(storageAccounts, ", ") + "\n")
	}

	return sb.String()
}

func gcpListBuckets(timeout time.Duration) string {
	var sb strings.Builder
	sb.WriteString("=== GCP Cloud Storage Bucket Enumeration ===\n\n")

	tokenResp := metadataGet(gcpTokenURL, timeout, map[string]string{"Metadata-Flavor": "Google"})
	if tokenResp == "" {
		sb.WriteString("[-] No service account available\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenResp)

	var tokenData struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(tokenResp), &tokenData); err != nil {
		sb.WriteString("[-] Could not parse service account token\n")
		return sb.String()
	}
	defer structs.ZeroString(&tokenData.AccessToken)

	sb.WriteString("[+] Service account token acquired\n\n")

	authHeaders := map[string]string{"Authorization": "Bearer " + tokenData.AccessToken}

	projectID := metadataGet(gcpProjectURL+"project-id", timeout, map[string]string{"Metadata-Flavor": "Google"})
	if projectID == "" {
		sb.WriteString("[-] Could not determine project ID\n")
		return sb.String()
	}
	sb.WriteString(fmt.Sprintf("[+] Project: %s\n\n", projectID))

	bucketsURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s&maxResults=50", projectID)
	resp := metadataGet(bucketsURL, timeout, authHeaders)
	if resp == "" {
		sb.WriteString("[-] GCS list buckets failed (no permissions or API not enabled)\n")
		return sb.String()
	}

	var listResult struct {
		Items []struct {
			Name         string `json:"name"`
			Location     string `json:"location"`
			StorageClass string `json:"storageClass"`
			TimeCreated  string `json:"timeCreated"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(resp), &listResult); err != nil {
		sb.WriteString("[-] Could not parse GCS response\n")
		return sb.String()
	}

	if len(listResult.Items) == 0 {
		sb.WriteString("[*] No GCS buckets found in project\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("[+] Found %d bucket(s):\n\n", len(listResult.Items)))

	for _, bucket := range listResult.Items {
		sb.WriteString(fmt.Sprintf("  gs://%s\n", bucket.Name))
		sb.WriteString(fmt.Sprintf("    Location: %s  Class: %s  Created: %s\n", bucket.Location, bucket.StorageClass, bucket.TimeCreated))

		objURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o?maxResults=5", bucket.Name)
		objResp := metadataGet(objURL, timeout, authHeaders)
		if objResp != "" {
			var objResult struct {
				Items []struct {
					Name string `json:"name"`
					Size string `json:"size"`
				} `json:"items"`
			}
			if json.Unmarshal([]byte(objResp), &objResult) == nil && len(objResult.Items) > 0 {
				sb.WriteString(fmt.Sprintf("    Sample objects (%d shown):\n", len(objResult.Items)))
				for _, obj := range objResult.Items {
					sb.WriteString(fmt.Sprintf("      %s (%s bytes)\n", obj.Name, obj.Size))
				}
			}
		}
	}

	return sb.String()
}
