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

### TLS Fingerprinting

Set `tls_fingerprint` to spoof browser JA3 fingerprints:
- `chrome`, `firefox`, `safari`, `edge` — fixed browser fingerprint (same JA3 every connection)
- `rotate` — randomly selects Chrome/Firefox/Safari/Edge per-connection (prevents JA3-based correlation)
- `random` — fully randomized fingerprint (not browser-matching)
- `go` — default Go TLS stack (no spoofing)

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

## Proxy Support

Fawkes supports routing C2 traffic through HTTP proxies, including enterprise proxies that require authentication.

| Parameter | Description |
|-----------|-------------|
| `proxy_url` | Proxy URL (e.g., `http://proxy:8080` or `socks5://127.0.0.1:1080`) |
| `proxy_user` | Proxy authentication username |
| `proxy_pass` | Proxy authentication password |
| `proxy_domain` | NTLM domain (e.g., `CORP`). When set, uses NTLM authentication instead of Basic |

**Authentication modes:**
- **No auth**: Leave `proxy_user` empty. Proxy is used without credentials.
- **Basic auth**: Set `proxy_user` and `proxy_pass`. Credentials are sent via standard `Proxy-Authorization: Basic` header.
- **NTLM auth**: Set `proxy_user`, `proxy_pass`, and `proxy_domain`. The agent performs a full NTLM handshake (Type1→Type2→Type3) during the CONNECT tunnel establishment. Required for enterprise proxies using Windows domain authentication.

**System proxy detection (Windows):** When `proxy_url` is empty, the agent queries WinHTTP for system proxy settings, including PAC file and WPAD auto-detection. On non-Windows platforms, `HTTP_PROXY`/`HTTPS_PROXY` environment variables are used.

**uTLS compatibility:** NTLM proxy authentication works with TLS fingerprinting — the proxy tunnel is established first, then the uTLS handshake occurs over the tunnel.

## OPSEC Considerations

- TLS fingerprinting prevents JA3-based detection
- URI randomization prevents static path signatures
- Content-Type cycling varies request appearance
- Body transforms disguise encrypted blobs as legitimate content
- Config vault encrypts C2 parameters in memory (AES-256-GCM)
- Sleep mask encrypts all agent data during sleep cycles
- Domain fronting hides true C2 destination from network observers
- Proxy credentials are XOR-encrypted in the binary (with `obfuscate_strings`)

## MITRE ATT&CK Mapping

- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573.001** — Encrypted Channel: Symmetric Cryptography
- **T1090.002** — Proxy: External Proxy
- **T1090.004** — Proxy: Domain Fronting
