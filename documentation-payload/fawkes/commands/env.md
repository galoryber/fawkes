+++
title = "env"
chapter = false
weight = 103
hidden = false
+++

## Summary

List environment variables on the target. Optionally filter by variable name (case-insensitive).

### Arguments

#### filter (optional)
Case-insensitive string to filter environment variable names. Only variables whose name contains the filter string will be shown.

## Usage
```
env [filter]
```

Example
```
env
env path
env user
```

## MITRE ATT&CK Mapping

- T1082
