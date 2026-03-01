+++
title = "net-shares"
chapter = false
weight = 145
hidden = false
+++

## Summary

Enumerates network shares on the local machine, remote hosts, or lists mapped network drives. Uses direct Win32 API calls (NetShareEnum, WNetEnumResource) — no subprocess creation.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Type | Description |
|----------|----------|------|-------------|
| action | Yes | ChooseOne | `local` - list shares on this machine, `remote` - list shares on target, `mapped` - list mapped network drives |
| target | No | String | Hostname or IP for remote action (e.g., DC01, 192.168.1.1) |

## Usage

List local shares:
```
net-shares -action local
```

List shares on a remote host:
```
net-shares -action remote -target DC01
```

List mapped network drives:
```
net-shares -action mapped
```

## Output Format

Returns JSON array of share entries, rendered by a browser script into a sortable table.

### JSON Structure
```json
[
  {"name": "C$", "type": "Disk (Admin)", "path": "C:\\", "remark": "Default share", "host": "", "provider": ""},
  {"name": "IPC$", "type": "IPC (Admin)", "path": "", "remark": "Remote IPC", "host": "", "provider": ""},
  {"name": "Users", "type": "Disk", "path": "C:\\Users", "remark": "", "host": "", "provider": ""}
]
```

### Browser Script Rendering

The browser script renders results as a color-coded sortable table:
- **Red** rows indicate **Admin shares** (e.g., C$, ADMIN$)
- **Blue** rows indicate **IPC shares** (e.g., IPC$)
- Default styling for standard shares

Columns: Name, Type, Path, Remark, Host, Provider.

## MITRE ATT&CK Mapping

- **T1135** - Network Share Discovery
