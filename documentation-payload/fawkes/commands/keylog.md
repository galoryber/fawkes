+++
title = "keylog"
chapter = false
weight = 48
hidden = false
+++

## Summary

Low-level keyboard logger using Windows `SetWindowsHookExW` with `WH_KEYBOARD_LL`. Captures all keystrokes system-wide with active window context (shows which application the user is typing in).

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `start` to begin capture, `stop` to stop and return data, `dump` to return data without stopping |

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

## Output Format

Captured keystrokes include window context headers:

```
[14:23:05] --- Google Chrome ---
Hello worl[BS]d

[14:23:12] --- Command Prompt ---
dir C:\Users[ENTER]
cd ..[ENTER]
```

Special keys are shown in brackets: `[ENTER]`, `[TAB]`, `[BS]` (backspace), `[DEL]`, `[ESC]`, `[F1]`-`[F12]`, `[CAPS]`, `[WIN]`, arrow keys.

## Notes

- **Mythic Keylogs**: When `stop` or `dump` returns captured keystrokes, they are automatically parsed by window title and sent to Mythic's Keylogs tracker with user attribution. Keylogs are searchable in the Mythic UI.
- The keylogger runs in a background goroutine and does not block the agent
- Only one keylogger instance can run at a time
- Window titles provide context for what application keystrokes belong to
- Modifier keys (Shift, Ctrl, Alt) are suppressed from output for readability
- The keyboard hook requires a message pump, which runs in the background thread

## MITRE ATT&CK Mapping

- **T1056.001** — Input Capture: Keylogging
