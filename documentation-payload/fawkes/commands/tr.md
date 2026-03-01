+++
title = "tr"
chapter = false
weight = 190
hidden = false
+++

## Summary

Translate, squeeze, or delete characters in file content. Like Unix `tr` — supports character classes (`[:lower:]`, `[:upper:]`, `[:digit:]`, etc.) and ranges (`a-z`).

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | Yes | | Path to file to process |
| from | No | | Characters to translate from (supports classes and ranges) |
| to | No | | Characters to translate to (pairs with from) |
| delete | No | | Characters to delete from content |
| squeeze | No | false | Squeeze consecutive repeated characters into one |

At least one of `from`/`to`, `delete`, or `squeeze` must be specified.

## Usage

Convert to uppercase:
```
tr -path /tmp/data.txt -from [:lower:] -to [:upper:]
```

Remove all digits:
```
tr -path file.txt -delete [:digit:]
```

Squeeze repeated characters:
```
tr -path file.txt -squeeze true
```

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery
