+++
title = "chmod"
chapter = false
weight = 110
hidden = false
+++

## Summary

Modify file and directory permissions using octal notation (e.g., `755`) or symbolic notation (e.g., `+x`, `u+rw`). Supports recursive directory operations.

Cross-platform — works from Windows, Linux, and macOS agents. POSIX permissions are fully supported on Linux/macOS; Windows has limited POSIX mapping.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| path | Yes | Path to file or directory |
| mode | Yes | Permissions — octal (`755`, `644`) or symbolic (`+x`, `u+rw`, `go-w`, `a=rx`) |
| recursive | No | Apply permissions recursively to directory contents (default: `false`) |

### Symbolic Mode Syntax

Format: `[who][operator][permissions]`

- **Who**: `u` (user/owner), `g` (group), `o` (other), `a` (all — default if omitted)
- **Operator**: `+` (add), `-` (remove), `=` (set exactly)
- **Permissions**: `r` (read), `w` (write), `x` (execute)
- Multiple clauses can be comma-separated: `u+rwx,go+rx`

## Usage

### Set executable permissions (octal)
```
chmod -path /tmp/payload.elf -mode 755
```

### Add execute permission for everyone (symbolic)
```
chmod -path ./script.sh -mode +x
```

### Set owner read-write, others read-only
```
chmod -path /tmp/config.txt -mode u+rw,go+r
```

### Recursive directory permissions
```
chmod -path /var/data -mode 644 -recursive true
```

## Output

```
[+] /tmp/payload.elf
    Before: rw-r--r-- (0644)
    After:  rwxr-xr-x (0755)
```

### Recursive output
```
[+] /var/data  rw-r--r-- → rw-rw-r--
[+] /var/data/file1.txt  rw-r--r-- → rw-rw-r--
[+] /var/data/file2.txt  rw-r--r-- → rw-rw-r--
[+] /var/data/subdir  rwxr-xr-x → rwxrwxr-x

[*] 4 items changed
```

## OPSEC Considerations

- **File metadata changes**: Permission changes update file metadata (ctime on Linux/macOS) which may be logged or detected
- **No subprocess**: Uses Go's `os.Chmod` — no external commands spawned
- **Windows limitations**: Windows maps POSIX permissions approximately; use Windows-native ACL tools for fine-grained Windows permission management

## MITRE ATT&CK Mapping

- T1222 — File and Directory Permissions Modification
