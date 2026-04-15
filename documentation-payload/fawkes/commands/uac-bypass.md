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

Bypass User Account Control (UAC) to escalate from medium integrity (standard user context) to high integrity (administrator). Eight techniques available: registry-based protocol handler hijacking, environment variable hijacking, INF file abuse, COM CLSID hijacking, and mock trusted directory abuse.

### Techniques

- **fodhelper** (default) — Hijacks the `ms-settings` protocol handler via `HKCU\Software\Classes\ms-settings\Shell\Open\command`, then launches `fodhelper.exe` which auto-elevates and reads the handler. Works on Windows 10/11.
- **computerdefaults** — Same `ms-settings` hijack as fodhelper, but triggers via `computerdefaults.exe`. Alternative if fodhelper is monitored.
- **sdclt** — Hijacks the `Folder` shell handler via `HKCU\Software\Classes\Folder\shell\open\command`, then launches `sdclt.exe`. Works on Windows 10.
- **eventvwr** — Hijacks the `mscfile` file association via `HKCU\Software\Classes\mscfile\Shell\Open\command`, then launches `eventvwr.exe` which auto-elevates and opens a `.msc` file through the hijacked handler. Works on Windows 10/11.
- **silentcleanup** — Overrides the `windir` environment variable in `HKCU\Environment`, then triggers the `SilentCleanup` scheduled task which runs with highest privileges and expands `%windir%` from the hijacked value. Works on Windows 10/11.
- **cmstp** — Writes a malicious INF file and launches `cmstp.exe /au` which auto-elevates and executes commands from the INF's `UnRegisterOCXs` section. Works on Windows 10/11.
- **dismhost** — Hijacks the DISM Package Manager COM object (CLSID `{3ad05575-8857-4850-9277-11b85bdb8e09}`) by registering a `LocalServer32` handler in HKCU. When `pkgmgr.exe` auto-elevates and CoCreates this CLSID, COM resolves HKCU first and launches the command at high integrity.
- **wusa** — Uses the mock trusted directory technique (evolution of the original wusa.exe /extract method). Creates a directory with a trailing space (`C:\Windows \System32\`) that passes Windows auto-elevation path validation, then copies an auto-elevating binary to it combined with the ms-settings registry hijack. Works on Windows 10/11.

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
- `eventvwr` — mscfile hijack via eventvwr.exe (Win10+)
- `silentcleanup` — Environment variable hijack via SilentCleanup task (Win10+)
- `cmstp` — INF file abuse via cmstp.exe (Win10+)
- `dismhost` — COM CLSID hijack via pkgmgr.exe (Win10+)
- `wusa` — Mock trusted directory + ms-settings hijack (Win10+)

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

Use eventvwr technique (mscfile hijack):
```
uac-bypass -technique eventvwr
```

Use silentcleanup technique (env var hijack):
```
uac-bypass -technique silentcleanup
```

Use cmstp technique (INF file abuse):
```
uac-bypass -technique cmstp -command "C:\path\to\payload.exe"
```

Use dismhost technique (COM CLSID hijack):
```
uac-bypass -technique dismhost
```

Use wusa technique (mock trusted directory):
```
uac-bypass -technique wusa
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

### Registry Hijack Techniques (fodhelper, computerdefaults, sdclt, eventvwr)
1. **Check elevation**: If the process token is already elevated, skip the bypass
2. **Set registry key**: Write the command to the protocol/file handler's `(Default)` value (and `DelegateExecute` where needed)
3. **Launch trigger**: Start the auto-elevating binary via ShellExecute
4. **Auto-elevation**: Windows auto-elevates the trigger binary (manifest flag). The binary reads the hijacked handler and executes the command at high integrity
5. **Cleanup**: After a jittered delay, all hijacked registry keys are shredded (3-pass overwrite) and removed

### Environment Variable Technique (silentcleanup)
1. **Check elevation**: If already elevated, skip
2. **Set env var**: Override `windir` in `HKCU\Environment` with a command string that hijacks the variable expansion
3. **Trigger task**: Run the `SilentCleanup` scheduled task via `schtasks.exe /run`, which runs with highest privileges and expands `%windir%`
4. **Cleanup**: Restore the original `windir` environment variable (or delete the override)

### INF File Technique (cmstp)
1. **Check elevation**: If already elevated, skip
2. **Write INF**: Create a temporary INF file with a `RunPreSetupCommandsSection` or `UnRegisterOCXs` section containing the target command
3. **Launch cmstp**: Start `cmstp.exe /au <inf_path>` via ShellExecute, which auto-elevates
4. **Cleanup**: After a jittered delay, the INF file is shredded (overwritten with random data) and deleted

### COM CLSID Hijack (dismhost)
1. **Check elevation**: If already elevated, skip
2. **Register COM hijack**: Create `HKCU\Software\Classes\CLSID\{3ad05575-...}\LocalServer32` pointing to the command
3. **Trigger elevation**: Launch `pkgmgr.exe` via ShellExecute (auto-elevates as a DISM component)
4. **COM activation**: `pkgmgr.exe` calls CoCreateInstance for the DismHost CLSID. COM resolves HKCU first and launches our command at high integrity
5. **Cleanup**: After a jittered delay, the CLSID keys are shredded and removed

### Mock Trusted Directory (wusa)
1. **Check elevation**: If already elevated, skip
2. **Create mock directory**: Create `C:\Windows \System32\` (trailing space) using `\\?\` prefix to bypass Windows path normalization
3. **Copy binary**: Copy `computerdefaults.exe` (auto-elevating) to the mock directory
4. **Set registry hijack**: Write the ms-settings protocol handler hijack (same as fodhelper technique)
5. **Launch from mock path**: Start the copied binary via ShellExecute. Windows auto-elevation check resolves the path via `GetLongPathNameW` (strips trailing space → trusted path), so it auto-elevates. The elevated binary reads the HKCU handler and executes the command
6. **Cleanup**: Shred registry keys and remove the mock directory tree

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
- T1218.003 — System Binary Proxy Execution: CMSTP (cmstp technique)
