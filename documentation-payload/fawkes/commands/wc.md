+++
title = "wc"
chapter = false
weight = 193
hidden = false
+++

## Summary

Count lines, words, characters, and bytes in files. Supports single file and directory mode with glob pattern filtering. Directory mode shows per-file counts with totals.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | Yes | | Path to file or directory |
| pattern | No | * | Glob pattern to filter files in directory mode |

## Usage

Count a single file:
```
wc -path /etc/passwd
```

Count all files in a directory:
```
wc -path /var/log
```

Count only log files in a directory:
```
wc -path /var/log -pattern *.log
```

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery
