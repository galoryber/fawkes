+++
title = "secure-delete"
chapter = false
weight = 172
hidden = false
+++

## Summary

Securely delete files, wipe data, or destroy boot records. Three modes:

- **delete** (default): Random data overwrite before removal (T1070.004)
- **wipe**: Aggressive patterned destruction — zeros, ones, alternating, random (T1485)
- **wipe-mbr**: Overwrite MBR/GPT boot record on a raw disk device, rendering the system unbootable (T1561)

{{% notice info %}}Cross-platform — works on Windows, Linux, and macOS{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | delete | `delete`: random overwrite. `wipe`: patterned destruction (T1485). `wipe-mbr`: destroy boot record (T1561) |
| path | Yes | | Path to file, directory, or disk device (for wipe-mbr) |
| passes | No | 3 (delete) / 7 (wipe) | Number of overwrite passes |
| confirm | No | | Safety gate: `DESTROY` required for wipe and wipe-mbr actions |

## Usage

Securely delete a single file (default 3 random passes):
```
secure-delete -path /tmp/payload.bin
```

Delete with extra passes:
```
secure-delete -path C:\Users\setup\tool.exe -passes 7
```

Recursively secure-delete a directory:
```
secure-delete -path /tmp/artifacts
```

### Data Destruction (T1485)

Aggressive wipe with patterned overwrite (zeros → ones → alternating → random):
```
secure-delete -action wipe -path /data/sensitive -confirm DESTROY
```

{{% notice warning %}}
Wipe is a destructive operation that cannot be reversed. The patterned overwrite (7 passes default) makes forensic recovery extremely difficult. Requires `-confirm DESTROY` safety gate.
{{% /notice %}}

### Disk Wipe: MBR/GPT Destruction (T1561)

Overwrite the Master Boot Record and GPT header on a raw disk device:
```
secure-delete -action wipe-mbr -path /dev/sda -confirm DESTROY
```

Windows:
```
secure-delete -action wipe-mbr -path \\.\PhysicalDrive0 -confirm DESTROY
```

{{% notice warning %}}
wipe-mbr destroys the boot record (first 1024 bytes) of a disk device. The system will be UNBOOTABLE after this operation. Requires root/Administrator. This simulates wiper malware behavior (e.g., NotPetya, WhisperGate). Only use in authorized purple team exercises.
{{% /notice %}}

## MITRE ATT&CK Mapping

- **T1070.004** — Indicator Removal: File Deletion
- **T1485** — Data Destruction (wipe action)
- **T1561** — Disk Wipe (wipe-mbr action)
