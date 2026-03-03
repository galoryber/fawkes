+++
title = "ssh-agent"
chapter = false
weight = 131
hidden = false
+++

{{% notice info %}}Linux/macOS Only{{% /notice %}}

## Summary

Enumerate SSH agent sockets on the system and list loaded keys (identities) from each agent. Discovers agent sockets via `SSH_AUTH_SOCK` environment variable and filesystem scanning of common locations (`/tmp/ssh-*`, `/run/user/*`, GNOME Keyring). Key fingerprints are automatically reported to Mythic's credential vault.

This is valuable for lateral movement: if SSH agent forwarding is enabled, operators can use discovered agent sockets to authenticate to remote hosts without having the actual private key files.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | No | list | `list` (connect and list keys) or `enum` (find sockets only) |
| socket | string | No | - | Path to a specific SSH agent socket |

## Usage

### List Loaded Keys (Default)

Discover all agent sockets and list their loaded keys:
```
ssh-agent
```

### Enumerate Sockets Only

Find agent sockets without connecting (less intrusive):
```
ssh-agent -action enum
```

### Query Specific Socket

Connect to a specific agent socket (e.g., from another user's forwarded agent):
```
ssh-agent -socket /tmp/ssh-XXXXXXXX/agent.12345
```

### Example Output (list)

```
Socket: /tmp/ssh-a1b2c3d4/agent.54321 (SSH_AUTH_SOCK) — 2 key(s)
  [1] ssh-ed25519 SHA256:abcdefghijklmnopqrstuvwxyz012345678901234 (256 bits) — admin@jumpbox
  [2] ssh-rsa SHA256:ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901234 — deploy@prod

Socket: /tmp/ssh-e5f6g7h8/agent.67890 (scan:/tmp/ssh-*) — 1 key(s)
  [3] ecdsa-sha2-nistp256 SHA256:xyzXYZ0123456789abcdefABCDEF0123456789ab (256 bits) — service@internal
```

### Example Output (enum)

```
Found 2 SSH agent socket(s):

  /tmp/ssh-a1b2c3d4/agent.54321  (SSH_AUTH_SOCK)
  /tmp/ssh-e5f6g7h8/agent.67890  (scan:/tmp/ssh-*)
```

## Socket Discovery Locations

| Location | Source | Description |
|----------|--------|-------------|
| `$SSH_AUTH_SOCK` | Environment | Current user's active agent |
| `/tmp/ssh-*/agent.*` | Filesystem scan | OpenSSH agent sockets (any user) |
| `/run/user/*/ssh-agent.*` | Filesystem scan | Systemd user session agents |
| `/run/user/*/keyring/ssh` | Filesystem scan | GNOME Keyring SSH agent |

## MITRE ATT&CK Mapping

- T1552.004 — Unsecured Credentials: Private Keys
