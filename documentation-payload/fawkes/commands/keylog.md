+++
title = "keylog"
chapter = false
weight = 48
hidden = false
+++

## Summary

Low-level keyboard logger with clipboard paste detection. Windows: `SetWindowsHookExW` with `WH_KEYBOARD_LL`. Linux: `/dev/input/event*` evdev interface. macOS: IOKit HID device reading. All platforms detect Ctrl+V/Cmd+V paste events and capture clipboard content inline.

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

Captured keystrokes include window context and paste detection on all platforms:

```
[14:23:05] --- Google Chrome ---
Hello worl[BS]d
[PASTE:https://example.com/api/token?key=secret123]

[14:23:12] --- Terminal ---
ssh root@10.0.0.1[ENTER]
[PASTE:P@ssw0rd123]
sudo apt update[ENTER]
```

Special keys are shown in brackets: `[ENTER]`, `[TAB]`, `[BS]` (backspace), `[DEL]`, `[ESC]`, `[F1]`-`[F12]`, `[CAPS]`, `[SUPER]`, arrow keys. Paste events show `[PASTE:content]` with up to 200 characters of clipboard content.

## Platform Notes

### Windows
- Uses `SetWindowsHookExW` with `WH_KEYBOARD_LL` for system-wide capture
- Includes active window title for context (shows which app keystrokes belong to)
- Detects Ctrl+V and captures clipboard content as `[PASTE:...]`
- Requires a message pump running in a background thread
- Uses `GetKeyNameTextW` for key name resolution

### Linux
- Uses `/dev/input/event*` evdev interface to read raw keyboard events
- Automatically detects keyboard devices via `/sys/class/input/*/device/capabilities/`
- Requires root or membership in the `input` group
- Tracks shift and ctrl state for correct output
- Detects Ctrl+V and captures clipboard content
- Window context tracking via `xdotool` or `xprop` (_NET_WM_NAME)
- Monitors all detected keyboard devices simultaneously

### macOS
- Uses IOKit HID device reading for keyboard event capture
- USB HID usage code mapping for key-to-character conversion
- Tracks frontmost application via `osascript` (System Events)
- Detects Cmd+V and captures clipboard content
- Requires root or Accessibility permissions

## Notes

- **Mythic Keylogs**: When `stop` or `dump` returns captured keystrokes, they are automatically parsed and sent to Mythic's Keylogs tracker with user attribution. Keylogs are searchable in the Mythic UI.
- **Clipboard Paste Detection**: Ctrl+V (Windows/Linux) and Cmd+V (macOS) trigger an inline clipboard read. Pasted content up to 200 characters is logged as `[PASTE:content]`.
- The keylogger runs in a background goroutine and does not block the agent
- Only one keylogger instance can run at a time
- Modifier keys (Shift, Ctrl, Alt, Cmd) are suppressed from output for readability

## MITRE ATT&CK Mapping

- **T1056.001** — Input Capture: Keylogging
