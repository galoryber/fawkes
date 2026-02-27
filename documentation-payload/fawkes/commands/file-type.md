+++
title = "file-type"
chapter = false
weight = 205
hidden = false
+++

## Summary

Identify file types by inspecting magic bytes (header signatures) without relying on file extensions. Supports 35+ file format signatures across executables, archives, documents, images, databases, crypto formats, media files, and system files. Can scan individual files or entire directories.

Useful for identifying disguised files, finding interesting targets for exfiltration, and triaging directories of unknown content.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | Yes | | Path to a file or directory to analyze |
| recursive | No | false | Recursively scan subdirectories |
| max_files | No | 100 | Maximum number of files to analyze in directory mode |

## Usage

Identify a single file:
```
file-type -path /tmp/suspicious.dat
```

Scan a directory:
```
file-type -path /home/user/Documents
```

Recursive scan with limit:
```
file-type -path /opt -recursive true -max_files 50
```

## Supported Signatures

| Category | Formats |
|----------|---------|
| Executables | PE (MZ), ELF, Mach-O (32/64/Universal), dylib |
| Archives | ZIP, GZIP, BZIP2, XZ, 7-Zip, RAR, Zstandard |
| Documents | PDF, Microsoft Office (OLE2) |
| Images | PNG, JPEG, GIF, BMP, TIFF |
| Databases | SQLite |
| Crypto | DER/ASN.1 certificates, LUKS encrypted volumes |
| Scripts | Shebang (#!) scripts |
| Media | MP4/MOV, MP3 (ID3), OGG, RIFF (WAV/AVI/WebP) |
| System | Windows Registry hives, EVTX event logs |
| Text | Auto-detected via character analysis (>85% printable) |

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery
