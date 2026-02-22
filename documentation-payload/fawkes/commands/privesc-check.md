+++
title = "privesc-check"
chapter = false
weight = 100
hidden = false
+++

## Summary

Linux privilege escalation enumeration. Scans for common privilege escalation vectors including SUID/SGID binaries, file capabilities, sudo rules, writable paths, and container detection.

{{% notice info %}}Linux Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | all | Check to perform: `all`, `suid`, `capabilities`, `sudo`, `writable`, `container` |

### Actions

- **all** — Run all checks and return a comprehensive report
- **suid** — Find SUID/SGID binaries in common paths, flag interesting ones (e.g., `find`, `python`, `docker`, `nmap`)
- **capabilities** — Enumerate file capabilities via `getcap` and current process capabilities from `/proc/self/status`
- **sudo** — Check `sudo -l` (non-interactive), read `/etc/sudoers` and `/etc/sudoers.d` if accessible
- **writable** — Find writable PATH directories (binary hijacking), writable sensitive files, world-writable dirs, UID 0 accounts
- **container** — Detect Docker (`.dockerenv`), Kubernetes (service account tokens), container cgroups, Docker socket, overlay FS, PID 1 process

## Usage

```
privesc-check -action all
privesc-check -action suid
privesc-check -action container
```

### Example Output (all)

```
=== LINUX PRIVILEGE ESCALATION CHECK ===

--- SUID/SGID Binaries ---
SUID binaries (15 found):
  /usr/bin/sudo (-rwsr-xr-x, 232680 bytes)
  /usr/bin/passwd (-rwsr-xr-x, 68208 bytes)
  ...

[!] INTERESTING SUID binaries (3):
  /usr/bin/find (-rwsr-xr-x, 280488 bytes)
  /usr/bin/python3.11 (-rwsr-xr-x, 5925136 bytes)

--- Sudo Rules ---
User setup may run the following commands:
    (ALL : ALL) NOPASSWD: ALL

[!] NOPASSWD rules detected — potential passwordless privilege escalation
[!] User has full sudo access (ALL)

--- Container Detection ---
No container indicators found — likely running on bare metal/VM host.
```

## MITRE ATT&CK Mapping

| Technique ID | Name |
|--------------|------|
| T1548 | Abuse Elevation Control Mechanism |
| T1548.001 | Setuid and Setgid |
| T1613 | Container and Resource Discovery |
| T1082 | System Information Discovery |
