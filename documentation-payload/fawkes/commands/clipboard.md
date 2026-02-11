+++
title = "clipboard"
chapter = false
weight = 108
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Read or write the Windows clipboard contents. Currently supports text (Unicode) clipboard data.

Useful for capturing clipboard contents during an engagement (passwords, sensitive data copied by the user) or for placing data on the clipboard for social engineering purposes.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action   | Yes      | read    | `read` to get clipboard contents, `write` to set clipboard contents |
| data     | No       | ""      | Text to write to clipboard (only used with `write` action) |

## Usage

### Read clipboard
```
clipboard -action read
```

### Write to clipboard
```
clipboard -action write -data "text to place on clipboard"
```

### Example Output (Read)
```
Clipboard contents (45 chars):
The quick brown fox jumps over the lazy dog.
```

### Example Output (Read, empty)
```
Clipboard is empty or does not contain text
```

### Example Output (Write)
```
Successfully wrote 26 characters to clipboard
```

## MITRE ATT&CK Mapping

- T1115 -- Clipboard Data
