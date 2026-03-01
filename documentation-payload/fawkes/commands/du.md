+++
title = "du"
chapter = false
weight = 118
hidden = false
+++

## Summary

Report disk usage for files and directories. Shows size breakdown by subdirectory, sorted by largest first. Useful for finding large files and understanding storage consumption on target systems.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | Yes | | Path to file or directory |
| max_depth | No | 1 | Maximum directory depth to display (-1 for unlimited) |

## Usage

Check disk usage of a directory:
```
du -path /var/log
```

Deep scan with unlimited depth:
```
du -path /home/user -max_depth -1
```

Check size of a single file:
```
du -path /tmp/payload.bin
```

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery
- **T1082** — System Information Discovery
