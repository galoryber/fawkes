+++
title = "windows"
chapter = false
weight = 160
hidden = false
+++

## Summary

Enumerate visible application windows on the target system. Shows what applications the user has open, including window handles, process IDs, process names, window classes, and titles.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | list | `list` — enumerate all visible windows. `search` — filter by title/process/class |
| filter | No | | Search string for filtering (case-insensitive substring match on title, process name, or class name) |
| all | No | false | Include hidden/invisible windows in results |

## Usage

**List all visible windows:**
```
windows
```

**Search for a specific application:**
```
windows -action search -filter "chrome"
```

**Include hidden windows:**
```
windows -all true
```

## Example Output

```
[*] Application Window Discovery (T1010)
[+] Found 7 windows

HWND     PID    Process                   Class                          Title
------------------------------------------------------------------------------------------------------------
0xD054A  4044   payload.exe               ConsoleWindowClass             C:\Users\setup\payload.exe
0x220504 7220   explorer.exe              CabinetWClass                  Downloads - File Explorer
0x104A0  7380   msedge.exe                Chrome_WidgetWin_1             Mythic - Microsoft Edge
0x3501A0 7220   explorer.exe              CabinetWClass                  Downloads - File Explorer
0x200A0  8492   SystemSettings.exe        Windows.UI.Core.CoreWindow     Settings
0xA0274  1468   ApplicationFrameHost.exe  ApplicationFrameWindow         Settings
0x100F8  7220   explorer.exe              Progman                        Program Manager
```

## Operational Notes

- Uses `EnumDesktopWindows` with WinSta0/Default desktop access
- Resolves process names via `QueryFullProcessImageName`
- Works best when the agent runs in the interactive user session
- Non-interactive sessions (SSH, services) may return 0 windows due to Windows session isolation

## MITRE ATT&CK Mapping

- **T1010** — Application Window Discovery
