+++
title = "find"
chapter = false
weight = 109
hidden = false
+++

## Summary

Recursively search for files by name pattern (glob). Useful for post-exploitation reconnaissance — locating config files, credentials, documents, etc.

Cross-platform — works on Windows, Linux, and macOS.

### Arguments

#### pattern (required)
Glob pattern to match filenames. Examples: `*.txt`, `*.conf`, `password*`, `*.kdbx`, `web.config`.

#### path (optional)
Directory to start the search in. Defaults to the current working directory.

#### max_depth (optional)
Maximum directory depth to traverse. Defaults to 10. Set to 1 to search only the specified directory.

## Usage
```
find -pattern *.conf
find -path C:\Users -pattern *.kdbx
find -path /etc -pattern *.conf -max_depth 3
```

### Example Output
```
Found 3 match(es) for '*.conf' in C:\Users\setup:

12.5 KB      C:\Users\setup\AppData\Local\app.conf
1.2 KB       C:\Users\setup\.ssh\config.conf
<DIR>        C:\Users\setup\configs.conf
```

Results are capped at 500 entries to avoid excessive output.

## MITRE ATT&CK Mapping

- T1083 — File and Directory Discovery
