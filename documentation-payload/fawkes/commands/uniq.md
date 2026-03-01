+++
title = "uniq"
chapter = false
weight = 194
hidden = false
+++

## Summary

Filter or count duplicate consecutive lines in a file. Similar to Unix `uniq`, processes adjacent duplicate lines. Use with `sort` first for global deduplication. Count mode sorts output by frequency for identifying the most common entries.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | Yes | | Path to file to process |
| count | No | false | Prefix lines with occurrence count (sorted by most frequent) |
| duplicate | No | false | Only show lines that appear more than once |
| unique_only | No | false | Only show lines that appear exactly once |

## Usage

Remove consecutive duplicates:
```
uniq -path /tmp/data.txt
```

Count occurrences (sorted by frequency):
```
uniq -path /var/log/logins.txt -count true
```

Show only duplicate entries:
```
uniq -path results.txt -duplicate true
```

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery
