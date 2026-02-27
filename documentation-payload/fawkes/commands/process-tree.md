+++
title = "process-tree"
chapter = false
weight = 155
hidden = false
+++

## Summary

Display process hierarchy as a tree showing parent-child relationships. Helps identify injection targets, security tools, and privilege context more effectively than the flat `ps` listing.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| pid | No | 0 | Show tree starting from this PID (default: all roots) |
| filter | No | | Only show processes matching this name filter |

## Usage

Show full process tree:
```
process-tree
```

Show tree rooted at PID 1234:
```
process-tree -pid 1234
```

Show only svchost processes and their children:
```
process-tree -filter svchost
```

## MITRE ATT&CK Mapping

- **T1057** — Process Discovery
