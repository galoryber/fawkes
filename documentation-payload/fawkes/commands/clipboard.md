+++
title = "clipboard"
chapter = false
weight = 108
hidden = false
+++

## Summary

Read, write, or continuously monitor clipboard contents. Supports text data with automatic credential pattern detection during monitoring.

On **Windows**, uses native Win32 API (OpenClipboard/GetClipboardData/SetClipboardData) for direct clipboard access.

On **macOS**, uses `pbpaste` (read) and `pbcopy` (write) CLI tools, which are always available on macOS.

### Monitor Mode

The `monitor` action starts a background polling loop that captures clipboard changes and auto-tags sensitive content (NTLM hashes, API keys, passwords, private keys, bearer tokens, connection strings, AWS keys, UNC paths, URLs with credentials).

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action   | Yes      | read    | `read`, `write`, `monitor`, `dump`, or `stop` |
| data     | No       | ""      | Text to write to clipboard (only used with `write` action) |
| interval | No       | 3       | Polling interval in seconds for monitor action |

## Usage

### Read clipboard
```
clipboard -action read
```

### Write to clipboard
```
clipboard -action write -data "text to place on clipboard"
```

### Start clipboard monitor
```
clipboard -action monitor -interval 5
```

### View captured clipboard entries
```
clipboard -action dump
```

### Stop clipboard monitor
```
clipboard -action stop
```

## MITRE ATT&CK Mapping

- T1115 -- Clipboard Data
