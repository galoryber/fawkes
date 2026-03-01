+++
title = "diff"
chapter = false
weight = 117
hidden = false
+++

## Summary

Compare two files and show differences in unified diff format. Uses LCS (Longest Common Subsequence) algorithm with configurable context lines. Useful for detecting configuration changes, identifying modified files, and comparing baseline snapshots.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| file1 | Yes | | Path to first file (original) |
| file2 | Yes | | Path to second file (modified) |
| context | No | 3 | Number of context lines around changes |

## Usage

Compare two config files:
```
diff -file1 /etc/passwd -file2 /tmp/passwd.bak
```

Compare with more context:
```
diff -file1 config.old -file2 config.new -context 5
```

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery
