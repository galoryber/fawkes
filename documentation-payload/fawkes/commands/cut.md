+++
title = "cut"
chapter = false
weight = 115
hidden = false
+++

## Summary

Extract fields or character ranges from file lines. Like Unix `cut` — supports field mode with custom delimiters and character position mode.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | Yes | | Path to file to process |
| delimiter | No | tab | Field delimiter character |
| fields | No | | Field numbers to extract (e.g., `1,3` or `1-3` or `2-`) |
| chars | No | | Character positions to extract (e.g., `1-10`) |

Either `fields` or `chars` must be specified.

## Usage

Extract username and shell from passwd:
```
cut -path /etc/passwd -delimiter : -fields 1,7
```

Extract columns 2-4 from CSV:
```
cut -path data.csv -delimiter , -fields 2-4
```

Extract first 10 characters per line:
```
cut -path file.txt -chars 1-10
```

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery
