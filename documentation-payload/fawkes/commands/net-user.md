+++
title = "net-user"
chapter = false
weight = 155
hidden = false
+++

## Summary

Manage local user accounts and group membership. Create users, delete users, change passwords, query account details, and manage local group membership.

- **Windows**: Uses Win32 netapi32.dll API — no subprocess creation, opsec-friendly
- **Linux**: Uses `useradd`/`userdel`/`usermod`/`chpasswd`/`gpasswd` system commands

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `-action` | Yes | Action to perform: `add`, `delete`, `info`, `password`, `group-add`, `group-remove` |
| `-username` | Yes | Target username |
| `-password` | For add/password | Account password |
| `-group` | For group-add/group-remove | Local group name |
| `-comment` | No | Account description (for add action) |

## Usage

### Create a new local user
```
net-user -action add -username backdoor -password "S3cure!P@ss" -comment "Backup admin"
```

### Get user info
```
net-user -action info -username setup
```

### Change a user's password
```
net-user -action password -username backdoor -password "N3w!P@ss"
```

### Add user to a privileged group
```
# Windows
net-user -action group-add -username backdoor -group Administrators

# Linux
net-user -action group-add -username backdoor -group sudo
```

### Remove user from a group
```
net-user -action group-remove -username backdoor -group "Remote Desktop Users"
```

### Delete a user
```
net-user -action delete -username backdoor
```

## Example Output

### Info (Windows)
```
User: setup
Full Name: setup
Privilege: Administrator
Flags: Enabled, Password Never Expires
Password Age: 45 days
Bad Password Count: 0
Number of Logons: 127
Last Logon: 1740268800 (Unix timestamp)
Logon Server: \\WIN1123H2
Primary Group ID: 513
```

### Info (Linux)
```
User:    gary
UID:     1000
GID:     1000
Comment: Gary Lobermier
Home:    /home/gary
Shell:   /bin/bash
Login:   Enabled
Password: Set
Groups:  gary : gary adm sudo docker
```

## How It Works

### Windows
All operations use **netapi32.dll Win32 API** — no subprocess creation, no `net.exe`:

| Action | API Call |
|--------|----------|
| add | `NetUserAdd` (level 1) |
| delete | `NetUserDel` |
| info | `NetUserGetInfo` (level 4) |
| password | `NetUserSetInfo` (level 1003) |
| group-add | `NetLocalGroupAddMembers` (level 3) |
| group-remove | `NetLocalGroupDelMembers` (level 3) |

### Linux
Operations use standard system administration commands:

| Action | Command |
|--------|---------|
| add | `useradd -m -s /bin/bash [-c comment] username` + `chpasswd` |
| delete | `userdel -r username` |
| info | Parse `/etc/passwd`, `/etc/shadow`, `groups` |
| password | `chpasswd` (via stdin pipe) |
| group-add | `usermod -aG group username` |
| group-remove | `gpasswd -d username group` |

## Operational Notes

- **Requires root/administrator privileges** for write operations (add, delete, password, group-add, group-remove)
- The `info` action parses `/etc/passwd` (all users) and `/etc/shadow` (root only) on Linux
- **Linux `info`** also reports password status (set/locked/empty), group memberships, and sudo access
- Linux creates users with `/bin/bash` shell and home directory by default
- **Linux `delete`** removes the home directory with `-r` flag
- Password credentials are zeroed from memory after use

## MITRE ATT&CK Mapping

- **T1136.001** — Create Account: Local Account
- **T1098** — Account Manipulation
