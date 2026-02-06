+++
title = "ps"
chapter = false
weight = 103
hidden = false
+++

## Summary

List running processes. Supports verbose output, PID filtering, and process name searching.

### Arguments

#### -v (optional)
Verbose output including command lines.

#### -i PID (optional)
Filter by a specific process ID.

#### filter (optional)
Search by process name.

## Usage
```
ps [-v] [-i PID] [filter]
```

Example
```
ps
ps -v
ps -i 1234
ps explorer
```

## MITRE ATT&CK Mapping

- T1057
