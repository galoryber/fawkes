+++
title = "download"
chapter = false
weight = 103
hidden = false
+++

## Summary

Download a file from the target system. Supports chunked file transfer for any file size. Integrates with the Mythic file browser.

### Arguments

#### path
Path to the file to download.

## Usage
```
download [path]
```

Example
```
download C:\Users\admin\Documents\passwords.xlsx
download /etc/shadow
```

## MITRE ATT&CK Mapping

- T1020
- T1030
- T1041
