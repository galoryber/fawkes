+++
title = "sort"
chapter = false
weight = 176
hidden = false
+++

## Summary

Sort lines of a file. Supports alphabetic (default), numeric, reverse, and unique modes. Useful for analyzing log files, organizing enumeration output, and identifying top events by frequency when combined with uniq.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | Yes | | Path to file to sort |
| reverse | No | false | Sort in reverse order |
| numeric | No | false | Sort by leading numeric value |
| unique | No | false | Remove duplicate lines after sorting |

## Usage

Sort a file alphabetically:
```
sort -path /tmp/data.txt
```

Sort numerically in reverse (largest first):
```
sort -path results.txt -numeric true -reverse true
```

Sort and deduplicate:
```
sort -path /var/log/users.txt -unique true
```

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery
