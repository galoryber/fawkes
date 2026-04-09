+++
title = "secure-delete"
chapter = false
weight = 172
hidden = false
+++

## Summary

Securely delete files by overwriting their contents before removal. Standard mode uses random data overwrites. Wipe mode uses aggressive patterned destruction (zeros, ones, alternating, random) for data destruction simulation (T1485).

{{% notice info %}}Cross-platform — works on Windows, Linux, and macOS{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | delete | `delete` (random overwrite) or `wipe` (patterned destruction T1485) |
| path | Yes | | Path to file or directory |
| passes | No | 3 (delete) / 7 (wipe) | Number of overwrite passes |
| confirm | No | | Safety gate: `DESTROY` required for wipe action |

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

## MITRE ATT&CK Mapping

- **T1070.004** — Indicator Removal: File Deletion
- **T1485** — Data Destruction (wipe action)
