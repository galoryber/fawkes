+++
title = "HTTPx"
chapter = false
weight = 10
hidden = false
+++

## Summary

The HTTPx profile is a malleable HTTP/HTTPS C2 profile with configurable request/response transforms. Unlike the basic HTTP profile which uses fixed encoding, HTTPx applies a user-defined transform pipeline to encode and decode traffic, allowing traffic to mimic legitimate web application patterns. It supports multiple callback domains with configurable rotation strategies.

{{% notice info %}}Requires the HTTPx C2 server profile to be installed and running on the Mythic server.{{% /notice %}}

## Build Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `callback_domains` | Array of callback domain URLs (e.g., `https://c2.example.com:8443`) | — (required) |
| `domain_rotation` | Domain rotation strategy: `fail-over`, `round-robin`, `random` | `fail-over` |
| `failover_threshold` | Consecutive failures before switching domains | `5` |
| `raw_c2_config` | JSON configuration file defining transforms and message placement | — (required) |
| `callback_interval` | Seconds between check-ins | `10` |
| `callback_jitter` | Jitter percentage (0-100) | `23` |
| `AESPSK` | Pre-shared AES-256 key | auto-generated |
| `killdate` | Agent expiration date (YYYY-MM-DD) | — |

## Configuration File Format

The `raw_c2_config` parameter accepts a JSON file that defines how messages are encoded and placed in HTTP requests/responses. The structure is:

```json
{
  "name": "profile-name",
  "get": {
    "verb": "GET",
    "uris": ["/api/v1/check", "/api/v2/status"],
    "client": {
      "headers": {"Accept": "application/json"},
      "parameters": {"_t": "timestamp"},
      "message": {"location": "cookie", "name": "session"},
      "transforms": [
        {"name": "base64url"},
        {"name": "prepend", "value": "token="}
      ]
    },
    "server": {
      "headers": {"Content-Type": "application/json"},
      "transforms": [
        {"name": "base64"},
        {"name": "prepend", "value": "{\"data\":\""},
        {"name": "append", "value": "\"}"}
      ]
    }
  },
  "post": {
    "verb": "POST",
    "uris": ["/api/v1/data"],
    "client": { ... },
    "server": { ... }
  }
}
```

### Message Location

The `message.location` field determines where the encrypted payload is placed in the HTTP request:

| Location | Description |
|----------|-------------|
| `body` | Message in the request body (default for POST) |
| `cookie` | Message in a cookie header (good for GET requests) |
| `query` | Message in a query parameter |
| `header` | Message in a custom HTTP header |

The `message.name` field specifies the cookie name, query parameter name, or header name.

### Transforms

Transforms are applied in order (index 0, 1, 2...) when sending, and in reverse order when receiving. The agent and server coordinate to ensure bidirectional encoding/decoding.

| Transform | Description | Parameters |
|-----------|-------------|------------|
| `base64` | Standard base64 encoding | — |
| `base64url` | URL-safe base64 (no padding) | — |
| `xor` | XOR encryption | `key`: hex-encoded XOR key |
| `netbios` | NetBIOS encoding (lowercase) | — |
| `netbiosu` | NetBIOS encoding (uppercase) | — |
| `prepend` | Prepend a string to the message | `value`: string to prepend |
| `append` | Append a string to the message | `value`: string to append |

### Domain Rotation

| Strategy | Behavior |
|----------|----------|
| `fail-over` | Use first domain until `failover_threshold` consecutive failures, then switch to next |
| `round-robin` | Cycle through domains sequentially for each request |
| `random` | Select a random domain for each request |

## Encryption

Identical to the HTTP profile:

1. JSON message serialized
2. AES-256-CBC encryption with random 16-byte IV
3. HMAC-SHA256 computed over IV + ciphertext
4. Format: `[IV (16B)][Ciphertext][HMAC (32B)]`
5. Callback UUID prepended
6. Client transforms applied
7. Placed at configured message location

The encryption occurs before transforms are applied, so transforms operate on the encrypted blob.

## OPSEC Considerations

- Transform pipelines allow traffic to mimic legitimate web application patterns
- Multi-domain support with rotation makes C2 infrastructure more resilient
- Message placement in cookies or headers avoids body-based inspection
- Prepend/append transforms can wrap encrypted data in legitimate-looking JSON, XML, or HTML
- Config vault encrypts all C2 parameters in memory (AES-256-GCM)
- Sleep mask encrypts agent data during sleep cycles

## Example: JSON API Mimicry

This configuration makes C2 traffic look like a REST API:

- GET requests: encrypted payload in a `session` cookie, base64url-encoded
- POST requests: encrypted payload in the body, wrapped in `{"data":"<base64>","ts":"..."}`
- Server responses: wrapped in `{"result":"<base64>","status":"ok"}`

## MITRE ATT&CK Mapping

- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573.001** — Encrypted Channel: Symmetric Cryptography
- **T1001.003** — Data Obfuscation: Protocol Impersonation
