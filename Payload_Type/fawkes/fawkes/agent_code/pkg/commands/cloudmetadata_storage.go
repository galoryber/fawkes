package commands

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type cloudStorageListing struct {
	Action   string             `json:"action"`
	Provider string             `json:"provider"`
	Host     string             `json:"host"`
	Role     string             `json:"role,omitempty"`
	Project  string             `json:"project,omitempty"`
	Account  string             `json:"account,omitempty"`
	Region   string             `json:"region,omitempty"`
	Buckets  []cloudBucketEntry `json:"buckets"`
	Error    string             `json:"error,omitempty"`
}

type cloudBucketEntry struct {
	Name         string             `json:"name"`
	URI          string             `json:"uri"`
	Created      string             `json:"created,omitempty"`
	Location     string             `json:"location,omitempty"`
	StorageClass string             `json:"storage_class,omitempty"`
	Objects      []cloudObjectEntry `json:"objects,omitempty"`
}

type cloudObjectEntry struct {
	Name string `json:"name"`
	Size int64  `json:"size,omitempty"`
}

func awsListBuckets(timeout time.Duration) string {
	listing := awsListBucketsStructured(timeout)
	data, err := json.Marshal(listing)
	if err != nil {
		return fmt.Sprintf("[-] JSON marshal failed: %v", err)
	}
	return string(data)
}

func awsListBucketsStructured(timeout time.Duration) cloudStorageListing {
	listing := cloudStorageListing{
		Action:   "cloud-storage",
		Provider: "aws",
	}

	h := awsHeaders(timeout)
	roles := metadataGet(awsCredsURL, timeout, h)
	if roles == "" {
		listing.Error = "No IAM role attached — cannot enumerate S3 buckets"
		return listing
	}

	role := strings.TrimSpace(strings.Split(roles, "\n")[0])
	credsJSON := metadataGet(awsCredsURL+role, timeout, h)
	if credsJSON == "" {
		listing.Error = "Could not retrieve IAM credentials"
		return listing
	}
	defer structs.ZeroString(&credsJSON)

	var creds struct {
		AccessKeyId     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
	}
	if err := json.Unmarshal([]byte(credsJSON), &creds); err != nil {
		listing.Error = "Could not parse IAM credentials"
		return listing
	}
	defer func() {
		structs.ZeroString(&creds.AccessKeyId)
		structs.ZeroString(&creds.SecretAccessKey)
		structs.ZeroString(&creds.Token)
	}()

	listing.Role = role

	region := metadataGet(awsMetaURL+"placement/region", timeout, h)
	if region == "" {
		region = "us-east-1"
	}
	listing.Region = region
	listing.Host = fmt.Sprintf("s3.%s.amazonaws.com", region)

	s3Endpoint := fmt.Sprintf("https://s3.%s.amazonaws.com/", region)
	resp := awsSignedGet(s3Endpoint, "Action=ListBuckets", creds.AccessKeyId, creds.SecretAccessKey, creds.Token, "s3", timeout)

	if resp == "" {
		resp = metadataGet("https://s3.amazonaws.com/", timeout, map[string]string{
			"X-Amz-Security-Token": creds.Token,
		})
	}

	if resp == "" {
		listing.Error = "S3 ListBuckets failed (no permissions or no buckets)"
		return listing
	}

	bucketNames := cloudExtractXMLValues(resp, "Name")
	creationDates := cloudExtractXMLValues(resp, "CreationDate")

	if len(bucketNames) == 0 {
		listing.Error = "No S3 buckets found (or ListBuckets denied)"
		return listing
	}

	for i, name := range bucketNames {
		entry := cloudBucketEntry{
			Name: name,
			URI:  "s3://" + name,
		}
		if i < len(creationDates) {
			entry.Created = creationDates[i]
		}

		bucketEndpoint := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/", name, region)
		listResp := awsSignedGet(bucketEndpoint, "list-type=2&max-keys=5", creds.AccessKeyId, creds.SecretAccessKey, creds.Token, "s3", timeout)
		if listResp != "" {
			keys := cloudExtractXMLValues(listResp, "Key")
			sizes := cloudExtractXMLValues(listResp, "Size")
			for j, key := range keys {
				obj := cloudObjectEntry{Name: key}
				if j < len(sizes) {
					if s, err := strconv.ParseInt(sizes[j], 10, 64); err == nil {
						obj.Size = s
					}
				}
				entry.Objects = append(entry.Objects, obj)
			}
		}

		listing.Buckets = append(listing.Buckets, entry)
	}

	return listing
}

func azureListStorageContainers(timeout time.Duration) string {
	listings := azureListStorageStructured(timeout)
	if len(listings) == 1 {
		data, err := json.Marshal(listings[0])
		if err != nil {
			return fmt.Sprintf("[-] JSON marshal failed: %v", err)
		}
		return string(data)
	}
	data, err := json.Marshal(listings)
	if err != nil {
		return fmt.Sprintf("[-] JSON marshal failed: %v", err)
	}
	return string(data)
}

func azureListStorageStructured(timeout time.Duration) []cloudStorageListing {
	tokenURL := azureMetadataBase + "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"
	tokenResp := metadataGet(tokenURL, timeout, map[string]string{"Metadata": "true"})
	if tokenResp == "" {
		return []cloudStorageListing{{
			Action:   "cloud-storage",
			Provider: "azure",
			Error:    "No managed identity available or Storage scope denied",
		}}
	}
	defer structs.ZeroString(&tokenResp)

	var tokenData struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(tokenResp), &tokenData); err != nil {
		return []cloudStorageListing{{
			Action:   "cloud-storage",
			Provider: "azure",
			Error:    "Could not parse managed identity token",
		}}
	}
	defer structs.ZeroString(&tokenData.AccessToken)

	authHeaders := map[string]string{
		"Authorization": "Bearer " + tokenData.AccessToken,
		"x-ms-version":  "2021-08-06",
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
		return []cloudStorageListing{{
			Action:   "cloud-storage",
			Provider: "azure",
			Error:    "No storage account names discovered from instance metadata",
		}}
	}

	var results []cloudStorageListing
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

		listing := cloudStorageListing{
			Action:   "cloud-storage",
			Provider: "azure",
			Host:     fmt.Sprintf("%s.blob.core.windows.net", account),
			Account:  account,
		}

		for _, container := range containerNames {
			entry := cloudBucketEntry{
				Name: container,
				URI:  fmt.Sprintf("https://%s.blob.core.windows.net/%s", account, container),
			}

			blobURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list&maxresults=5", account, container)
			blobResp := metadataGet(blobURL, timeout, authHeaders)
			if blobResp != "" {
				blobNames := cloudExtractXMLValues(blobResp, "Name")
				for _, blob := range blobNames {
					entry.Objects = append(entry.Objects, cloudObjectEntry{Name: blob})
				}
			}

			listing.Buckets = append(listing.Buckets, entry)
		}

		results = append(results, listing)
	}

	if len(results) == 0 {
		return []cloudStorageListing{{
			Action:   "cloud-storage",
			Provider: "azure",
			Error:    "No accessible storage accounts found among candidates: " + strings.Join(storageAccounts, ", "),
		}}
	}

	return results
}

func gcpListBuckets(timeout time.Duration) string {
	listing := gcpListBucketsStructured(timeout)
	data, err := json.Marshal(listing)
	if err != nil {
		return fmt.Sprintf("[-] JSON marshal failed: %v", err)
	}
	return string(data)
}

func gcpListBucketsStructured(timeout time.Duration) cloudStorageListing {
	listing := cloudStorageListing{
		Action:   "cloud-storage",
		Provider: "gcp",
		Host:     "storage.googleapis.com",
	}

	tokenResp := metadataGet(gcpTokenURL, timeout, map[string]string{"Metadata-Flavor": "Google"})
	if tokenResp == "" {
		listing.Error = "No service account available"
		return listing
	}
	defer structs.ZeroString(&tokenResp)

	var tokenData struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(tokenResp), &tokenData); err != nil {
		listing.Error = "Could not parse service account token"
		return listing
	}
	defer structs.ZeroString(&tokenData.AccessToken)

	authHeaders := map[string]string{"Authorization": "Bearer " + tokenData.AccessToken}

	projectID := metadataGet(gcpProjectURL+"project-id", timeout, map[string]string{"Metadata-Flavor": "Google"})
	if projectID == "" {
		listing.Error = "Could not determine project ID"
		return listing
	}
	listing.Project = projectID

	bucketsURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s&maxResults=50", projectID)
	resp := metadataGet(bucketsURL, timeout, authHeaders)
	if resp == "" {
		listing.Error = "GCS list buckets failed (no permissions or API not enabled)"
		return listing
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
		listing.Error = "Could not parse GCS response"
		return listing
	}

	if len(listResult.Items) == 0 {
		listing.Error = "No GCS buckets found in project"
		return listing
	}

	for _, bucket := range listResult.Items {
		entry := cloudBucketEntry{
			Name:         bucket.Name,
			URI:          "gs://" + bucket.Name,
			Created:      bucket.TimeCreated,
			Location:     bucket.Location,
			StorageClass: bucket.StorageClass,
		}

		objURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o?maxResults=5", bucket.Name)
		objResp := metadataGet(objURL, timeout, authHeaders)
		if objResp != "" {
			var objResult struct {
				Items []struct {
					Name string `json:"name"`
					Size string `json:"size"`
				} `json:"items"`
			}
			if json.Unmarshal([]byte(objResp), &objResult) == nil {
				for _, obj := range objResult.Items {
					o := cloudObjectEntry{Name: obj.Name}
					if s, err := strconv.ParseInt(obj.Size, 10, 64); err == nil {
						o.Size = s
					}
					entry.Objects = append(entry.Objects, o)
				}
			}
		}

		listing.Buckets = append(listing.Buckets, entry)
	}

	return listing
}
