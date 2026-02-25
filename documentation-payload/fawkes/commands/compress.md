+++
title = "compress"
chapter = false
weight = 120
hidden = false
+++

## Summary

Create, list, or extract zip archives for data staging and exfiltration preparation. Supports recursive directory archiving with pattern filtering, depth limits, and file size caps.

Cross-platform — works on Windows, Linux, and macOS.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | create | `create` (archive files), `list` (show zip contents), `extract` (unzip) |
| path | Yes | — | Source: file/directory (create), zip file (list/extract) |
| output | No | auto | Output: zip file (create), directory (extract). Auto-generated if omitted |
| pattern | No | all files | Glob pattern to filter files (e.g. `*.txt`, `*.docx`, `password*`) |
| max_depth | No | 10 | Maximum directory recursion depth |
| max_size | No | 104857600 (100MB) | Skip files larger than this (bytes) |

## Usage

### Create an archive of a directory
```
compress -action create -path C:\Users\target\Documents -output C:\Users\target\Downloads\docs.zip
```

### Archive only specific file types
```
compress -action create -path /etc -pattern *.conf -output /tmp/configs.zip
```

### List archive contents
```
compress -action list -path C:\Users\target\Downloads\docs.zip
```

### Extract files from archive
```
compress -action extract -path /tmp/configs.zip -output /tmp/extracted
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

- **Cross-platform**: Uses Go stdlib `archive/zip` — no external dependencies
- **Pattern filtering**: Glob patterns for selective archiving/extraction
- **Depth limiting**: Control recursion depth for large directory trees
- **Size limiting**: Skip large files to keep archives manageable
- **Auto output path**: Generates output path from source if not specified
- **Zip slip protection**: Extract validates paths to prevent directory traversal
- **Compression**: Uses Deflate algorithm for optimal compression ratio

## OPSEC Considerations

- Archive creation writes a new file to disk — consider cleanup after exfiltration
- `compress create` followed by `download` is the standard exfil staging workflow
- Large directory archiving may cause noticeable disk I/O
- The zip file format is not encrypted — use `download` over an encrypted C2 channel

## MITRE ATT&CK Mapping

- **T1560.001** — Archive Collected Data: Archive via Utility
