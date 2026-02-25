+++
title = "ads"
chapter = false
weight = 121
hidden = false
+++

## Summary

Manage NTFS Alternate Data Streams (ADS) — write, read, list, or delete hidden data streams attached to files. ADS is an NTFS feature that allows multiple data streams per file; the default stream (`:$DATA`) contains the visible file content, while alternate streams are hidden from standard file browsers and directory listings.

Common uses in red team operations:
- Hide shellcode, tools, or configuration data inside legitimate files
- Stash exfiltration data before collection
- Discover existing ADS (Zone.Identifier from downloads, SmartScreen markers)

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | list | Action: `write`, `read`, `list`, or `delete` |
| file | Yes | | Target file or directory path |
| stream | No | | Stream name (without colon prefix). Required for write/read/delete |
| data | No | | Data to write (text or hex-encoded). Required for write |
| hex | No | false | If true, data is hex-encoded bytes (write) or output as hex dump (read) |

## Usage

```
# List alternate data streams on a file
ads -action list -file C:\Users\setup\Downloads\report.docx

# List all files with ADS in a directory
ads -action list -file C:\Users\setup\Downloads

# Write text data to a hidden stream
ads -action write -file C:\Windows\Temp\legit.txt -stream config -data "callback=192.168.1.1"

# Write binary data (hex-encoded) to a stream
ads -action write -file C:\Windows\Temp\legit.txt -stream payload -data 4d5a90 -hex true

# Read a stream
ads -action read -file C:\Windows\Temp\legit.txt -stream config

# Read binary stream as hex dump
ads -action read -file C:\Windows\Temp\legit.txt -stream payload -hex true

# Delete a stream
ads -action delete -file C:\Windows\Temp\legit.txt -stream config
```

### Common ADS Found in the Wild

| Stream Name | Source |
|-------------|--------|
| `:Zone.Identifier` | Mark of the Web — added by browsers/email clients to downloaded files |
| `:SmartScreen` | Windows SmartScreen reputation data |
| `:$DATA` | Default data stream (the normal file content) |

### OPSEC Notes

- Uses standard Windows file APIs (CreateFile, ReadFile, WriteFile) with `:stream` syntax
- Stream enumeration uses `FindFirstStreamW` / `FindNextStreamW` (kernel32.dll)
- ADS are invisible to `dir`, Explorer, and most file listing tools
- ADS are preserved during file copy on NTFS but lost when copying to FAT32/exFAT
- Deleting the parent file removes all its ADS
- Some EDR products monitor ADS creation

## MITRE ATT&CK Mapping

- **T1564.004** - Hide Artifacts: NTFS File Attributes
