+++
title = "compress"
chapter = false
weight = 120
hidden = false
+++

## Summary

Create, list, or extract zip and tar.gz archives for data staging and exfiltration preparation. Supports recursive directory archiving with pattern filtering, depth limits, and file size caps.

Cross-platform — works on Windows, Linux, and macOS.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | create | `create` (archive files), `list` (show contents), `extract` (unarchive) |
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
- `compress create` followed by `download` is the standard exfil staging workflow
- Large directory archiving may cause noticeable disk I/O
- Archive files are not encrypted — use `download` over an encrypted C2 channel
- tar.gz is the standard format on Linux/macOS; zip is more common on Windows

## MITRE ATT&CK Mapping

- **T1560.001** — Archive Collected Data: Archive via Utility
