+++
title = "keylog"
chapter = false
weight = 48
hidden = false
+++

## Summary

Low-level keyboard logger. Windows: `SetWindowsHookExW` with `WH_KEYBOARD_LL` captures all keystrokes system-wide with active window context. Linux: `/dev/input/event*` evdev interface captures keystrokes from all keyboard devices.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `start` to begin capture, `stop` to stop and return data, `dump` to return data without stopping, `status` to check state/buffer, `clear` to reset buffer without stopping |

## Usage

### Start the keylogger
```
keylog -action start
```

### View captured keystrokes (without stopping)
```
keylog -action dump
```

### Stop the keylogger and return all captured data
```
keylog -action stop
```

### Check keylogger status (is it running? how much data?)
```
keylog -action status
```

### Clear the buffer without stopping
```
keylog -action clear
```

## Output Format

Captured keystrokes include window context headers (Windows):

```
[14:23:05] --- Google Chrome ---
Hello worl[BS]d

[14:23:12] --- Command Prompt ---
dir C:\Users[ENTER]
cd ..[ENTER]
```

Linux output (no window context):

```
ssh root@10.0.0.1[ENTER]
P@ssw0rd123[ENTER]
sudo apt update[ENTER]
```

Special keys are shown in brackets: `[ENTER]`, `[TAB]`, `[BS]` (backspace), `[DEL]`, `[ESC]`, `[F1]`-`[F12]`, `[CAPS]`, `[SUPER]`, arrow keys.

## Platform Notes

### Windows
- Uses `SetWindowsHookExW` with `WH_KEYBOARD_LL` for system-wide capture
- Includes active window title for context (shows which app keystrokes belong to)
- Requires a message pump running in a background thread
- Uses `GetKeyNameTextW` for key name resolution

### Linux
- Uses `/dev/input/event*` evdev interface to read raw keyboard events
- Automatically detects keyboard devices via `/sys/class/input/*/device/capabilities/`
- Requires root or membership in the `input` group
- Tracks shift state for correct uppercase/symbol output
- Monitors all detected keyboard devices simultaneously
- No window context (headless-compatible)

## Notes

- **Mythic Keylogs**: When `stop` or `dump` returns captured keystrokes, they are automatically parsed and sent to Mythic's Keylogs tracker with user attribution. Keylogs are searchable in the Mythic UI.
- The keylogger runs in a background goroutine and does not block the agent
- Only one keylogger instance can run at a time
- Modifier keys (Shift, Ctrl, Alt) are suppressed from output for readability

## MITRE ATT&CK Mapping

- **T1056.001** — Input Capture: Keylogging
