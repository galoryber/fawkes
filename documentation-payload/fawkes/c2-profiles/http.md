+++
title = "HTTP"
chapter = false
weight = 5
hidden = false
+++

## Summary

The HTTP profile is the default egress profile for Fawkes. The agent polls the Mythic server for tasking over HTTP or HTTPS, posting responses back via the same channel. All communication is AES-256-CBC encrypted with HMAC-SHA256 authentication.

## Build Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `callback_host` | C2 server URL (e.g., `http://192.168.1.100`) | — |
| `callback_port` | C2 server port | `80` |
| `callback_interval` | Seconds between check-ins | `10` |
| `callback_jitter` | Jitter percentage (0-100) | `23` |
| `get_uri` | URI path for GET requests (supports randomization tokens) | `index` |
| `post_uri` | URI path for POST requests (supports randomization tokens) | `data` |
| `query_path_name` | Query parameter name for GET requests | `q` |
| `headers` | Additional HTTP headers (JSON dictionary) | — |

## Malleable C2 Features

### URI Randomization

The `get_uri` and `post_uri` parameters support tokens that are resolved per-request:

- `{rand:N}` — N random hex characters (e.g., `/api/{rand:8}` produces `/api/a3f82b1c`)
- `{int:M-N}` — random integer in range (e.g., `/v{int:1-3}/status` produces `/v2/status`)

Example: `get_uri=/api/v{int:1-3}/{rand:8}/check` generates unique paths for every request.

### Content-Type Cycling

Set `content_types` to a comma-separated list of MIME types. The agent cycles through them round-robin for each POST request.

Example: `content_types=application/json,text/plain,application/x-www-form-urlencoded`

### Body Transforms

Set `body_transforms` to a comma-separated transform chain. Transforms are applied to the HTTP body **after** AES encryption and base64 encoding (outbound) and **reversed before** base64 decoding (inbound).

{{% notice warning %}}
The C2 server must apply matching reverse transforms. Without server-side configuration, the server will not understand transformed payloads.
{{% /notice %}}

**Available transforms:**

| Transform | Syntax | Description |
|-----------|--------|-------------|
| Base64 | `base64` | Double base64 encoding |
| Hex | `hex` | Hex encoding |
| Gzip | `gzip` | Gzip compression (reduces payload size) |
| XOR | `xor:<hex_key>` | XOR with repeating key (e.g., `xor:DEADBEEF`) |
| Prepend | `prepend:<hex_bytes>` | Prepend fixed bytes |
| Append | `append:<hex_bytes>` | Append fixed bytes |
| File Mask | `mask:<type>` | Wrap in file headers: `png`, `gif`, `jpeg`, `pdf` |
| NetBIOS | `netbios` | NetBIOS-style byte encoding (A-P alphabet) |

**Example chains:**

- `gzip,mask:png` — Compress then wrap as PNG image download
- `gzip,base64` — Compress then double-encode for ASCII transport
- `prepend:2F2F,append:0A` — Wrap data with `//` prefix and newline suffix

### TLS Fingerprinting

Set `tls_fingerprint` to spoof browser JA3 fingerprints: `chrome`, `firefox`, `safari`, `edge`, `random`, `go` (default).

### Domain Fronting

Set `host_header` to override the HTTP Host header for CDN domain fronting (e.g., set `callback_host` to the CDN IP but `host_header` to `legitimate.example.com`).

### Automatic Failover

Set `fallback_hosts` to comma-separated backup URLs. If the primary C2 is unreachable, the agent automatically rotates through fallback URLs.

## Encryption

All messages use AES-256-CBC encryption with HMAC-SHA256 authentication:

1. JSON message is serialized
2. AES-256-CBC encryption with random 16-byte IV
3. HMAC-SHA256 computed over IV + ciphertext
4. Format: `[IV (16B)][Ciphertext][HMAC (32B)]`
5. Callback UUID prepended
6. Base64 encoded
7. Body transforms applied (if configured)

## OPSEC Considerations

- TLS fingerprinting prevents JA3-based detection
- URI randomization prevents static path signatures
- Content-Type cycling varies request appearance
- Body transforms disguise encrypted blobs as legitimate content
- Config vault encrypts C2 parameters in memory (AES-256-GCM)
- Sleep mask encrypts all agent data during sleep cycles
- Domain fronting hides true C2 destination from network observers

## MITRE ATT&CK Mapping

- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573.001** — Encrypted Channel: Symmetric Cryptography
- **T1090.004** — Proxy: Domain Fronting
