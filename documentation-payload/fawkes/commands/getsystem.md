+++
title = "getsystem"
chapter = false
weight = 104
hidden = false
+++

## Summary

Cross-platform privilege escalation to root/SYSTEM.

- **Windows:** Token theft from SYSTEM process (steal) or DCOM potato (SeImpersonatePrivilege)
- **Linux:** Enumerate escalation vectors (check) or attempt elevation via sudo
- **macOS:** Enumerate vectors (check), sudo elevation, or osascript admin prompt

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| technique | No | check | Escalation technique (see platform sections) |

### Windows Techniques

| Technique | Requirements | Description |
|-----------|-------------|-------------|
| steal | Admin/SeDebugPrivilege | Steal token from SYSTEM process (winlogon, lsass, services) |
| potato | SeImpersonatePrivilege | DCOM OXID resolution hook + named pipe impersonation |

### Linux Techniques

| Technique | Requirements | Description |
|-----------|-------------|-------------|
| check | None | Enumerate escalation vectors: sudo NOPASSWD, SUID binaries, capabilities, writable /etc/passwd, docker group |
| sudo | sudo access (NOPASSWD or cached) | Attempt elevation via sudo |

### macOS Techniques

| Technique | Requirements | Description |
|-----------|-------------|-------------|
| check | None | Enumerate vectors: sudo NOPASSWD, admin group, TCC permissions, SUID binaries |
| sudo | sudo access | Attempt elevation via sudo |
| osascript | Admin group membership | Trigger admin auth dialog via AppleScript (visible to user) |

## Usage

```
# === Windows ===
getsystem
getsystem -technique steal
getsystem -technique potato

# === Linux ===
# Enumerate privilege escalation vectors
getsystem -technique check

# Attempt elevation via sudo (if cached or NOPASSWD)
getsystem -technique sudo

# === macOS ===
getsystem -technique check
getsystem -technique sudo
getsystem -technique osascript
```

## Example Output (Linux check)

```json
{
  "current_identity": "user (uid=1000, gid=1000)",
  "uid": 1000,
  "vectors": [
    {
      "method": "sudo-cached",
      "description": "Sudo credentials are cached",
      "risk": "high"
    },
    {
      "method": "docker",
      "description": "Current user is in the docker group",
      "risk": "high"
    }
  ],
  "total": 2
}
```

## Operational Notes

- **Windows:** Use `rev2self` to revert to original context after token theft
- **Linux:** `check` technique runs `sudo -l` which may generate auth log entries. SUID check reads filesystem metadata only
- **macOS:** `osascript` technique shows a visible dialog to the user — use only when social engineering is acceptable
- **Vectors detected (Linux):** sudo NOPASSWD, cached sudo, exploitable SUID (34 known GTFOBins), cap_setuid capabilities, writable /etc/passwd, docker group
- **Vectors detected (macOS):** sudo NOPASSWD, cached sudo, admin group, TCC permissions, SUID binaries

## MITRE ATT&CK Mapping

- **T1134.001** — Token Impersonation/Theft (Windows steal)
- **T1548.001** — Setuid/Setgid (Linux SUID exploitation)
- **T1548.003** — Sudo and Sudo Caching (Linux/macOS sudo)
- **T1059.002** — AppleScript (macOS osascript)
