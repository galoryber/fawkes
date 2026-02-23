+++
title = "curl"
chapter = false
weight = 115
hidden = false
+++

## Summary

Make HTTP/HTTPS requests from the agent's network perspective. Useful for accessing cloud metadata endpoints, probing internal services, checking web application health, and performing SSRF-style requests from a compromised host.

Supports all standard HTTP methods, custom headers, request bodies, response size limits, and three output modes.

## Arguments

| Argument | Required | Type | Default | Description |
|----------|----------|------|---------|-------------|
| url | Yes | string | | Target URL (http:// or https://) |
| method | No | choice | GET | HTTP method: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH |
| body | No | string | | Request body for POST/PUT/PATCH |
| headers | No | string | | Custom headers as JSON object: `{"Key": "Value"}` |
| output | No | choice | full | Output format: full (headers+body), body, headers |
| timeout | No | number | 30 | Request timeout in seconds |
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
