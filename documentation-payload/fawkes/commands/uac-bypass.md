+++
title = "uac-bypass"
chapter = false
weight = 107
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Bypass User Account Control (UAC) to escalate from medium integrity (standard user context) to high integrity (administrator). Uses registry-based protocol handler hijacking to redirect auto-elevating Windows binaries to execute an arbitrary command at elevated privileges.

### Techniques

- **fodhelper** (default) — Hijacks the `ms-settings` protocol handler via `HKCU\Software\Classes\ms-settings\Shell\Open\command`, then launches `fodhelper.exe` which auto-elevates and reads the handler. Works on Windows 10/11.
- **computerdefaults** — Same `ms-settings` hijack as fodhelper, but triggers via `computerdefaults.exe`. Alternative if fodhelper is monitored.
- **sdclt** — Hijacks the `Folder` shell handler via `HKCU\Software\Classes\Folder\shell\open\command`, then launches `sdclt.exe`. Works on Windows 10.

### Requirements

- **Medium integrity** — The agent must be running at medium integrity (non-elevated). If already elevated, the command reports success and suggests using `getsystem` instead.
- **Local admin group** — The user must be a member of the local Administrators group (UAC splits admin tokens into medium/high integrity).
- **Default UAC policy** — "Always notify" UAC setting may block these techniques. Default/lower settings work.
- **No admin required** — All registry writes are to HKCU (user hive).

### Arguments

#### technique
The UAC bypass technique to use. Default: `fodhelper`.
- `fodhelper` — ms-settings hijack via fodhelper.exe (most reliable, Win10+)
- `computerdefaults` — ms-settings hijack via computerdefaults.exe (Win10+)
- `sdclt` — Folder handler hijack via sdclt.exe (Win10)

#### command
The command or executable path to run at elevated privileges. Default: the agent's own executable path (spawns a new elevated callback).

## Usage

Bypass UAC with default settings (fodhelper, self-spawn):
```
uac-bypass
```

Bypass UAC with a specific technique:
```
uac-bypass -technique computerdefaults
```

Run a custom command elevated:
```
uac-bypass -command "C:\Windows\System32\cmd.exe /c whoami > C:\temp\elevated.txt"
```

Use sdclt technique:
```
uac-bypass -technique sdclt
```

## Example Output

### Successful Bypass (Medium Integrity)
```
[*] UAC Bypass Technique: fodhelper
[*] Trigger binary: C:\Windows\System32\fodhelper.exe
[*] Elevated command: C:\Users\user\Downloads\payload.exe

[*] Step 1: Setting registry key...
[+] Registry set: HKCU\Software\Classes\ms-settings\Shell\Open\command
[*] Step 2: Launching trigger binary...
[+] Launched C:\Windows\System32\fodhelper.exe (PID: 4532)
[*] Step 3: Cleaning up registry...
[+] Registry keys removed

[+] UAC bypass triggered successfully.
[*] If successful, a new elevated callback should appear shortly.
[*] The elevated process runs at high integrity (admin).
```

### Already Elevated
```
Already running at high integrity (elevated). UAC bypass not needed.
Use getsystem to escalate to SYSTEM.
```

## How It Works

1. **Check elevation**: If the process token is already elevated, skip the bypass
2. **Set registry key**: Write the command to the protocol handler's `(Default)` value and set an empty `DelegateExecute` value (forces Windows to use the command handler instead of the normal protocol)
3. **Launch trigger**: Start the auto-elevating binary (fodhelper.exe, computerdefaults.exe, or sdclt.exe)
4. **Auto-elevation**: Windows auto-elevates the trigger binary (it's in the manifest). The binary reads the hijacked handler and executes the command at high integrity
5. **Cleanup**: After a brief delay, all hijacked registry keys are removed

## Workflow

Typical escalation path:
```
1. whoami                          # Verify medium integrity
2. uac-bypass                      # Trigger bypass (new elevated callback)
3. [switch to new callback #N+1]   # Use the elevated callback
4. whoami                          # Verify high integrity
5. getsystem                       # Optionally escalate to SYSTEM
```

## MITRE ATT&CK Mapping

- T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control
