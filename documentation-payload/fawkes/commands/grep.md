+++
title = "grep"
chapter = false
weight = 119
hidden = false
+++

## Summary

Search file contents for patterns using regex. Cross-platform recursive file search with extension filtering, case-insensitive mode, context lines, and automatic binary file skipping.

Useful for credential discovery (passwords in config files), sensitive data enumeration, and post-exploitation reconnaissance.

Cross-platform — works on Windows, Linux, and macOS.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| pattern | Yes | — | Search pattern (regex supported) |
| path | No | . (current dir) | File or directory to search |
| extensions | No | all text files | Filter by extensions (comma-separated, e.g. `.txt,.xml,.config`) |
| ignore_case | No | false | Case-insensitive search |
| max_results | No | 100 | Maximum number of matches returned |
| context | No | 0 | Number of context lines before each match |
| max_depth | No | 10 | Maximum directory recursion depth |
| max_file_size | No | 10485760 (10MB) | Skip files larger than this (bytes) |

## Usage

```
# Search for passwords in config files
grep -pattern "password" -path C:\Users -extensions .txt,.xml,.ini,.config -ignore_case

# Search for API keys with regex
grep -pattern "(api[_-]?key|secret|token)\s*[:=]" -path /etc -ignore_case

# Search a single file
grep -pattern "ConnectionString" -path C:\inetpub\wwwroot\web.config

# Search with context lines
grep -pattern "FAILED" -path /var/log -extensions .log -context 3

# Search Linux config files for credentials
grep -pattern "password|passwd|secret" -path /etc -extensions .conf,.ini,.cfg,.yaml -ignore_case -max_results 20
```

## Example Output

### Windows — Config File Search
```
Found 3 matches in C:\Users\setup (26 files searched):

=== C:\Users\setup\Downloads\SysinternalsSuite\Eula.txt ===
28: ...passwords, paths to files accessed...

=== C:\Users\setup\Downloads\SysinternalsSuite\readme.txt ===
18: Autologon - Bypass password screen during logon.
102: PsPasswd - Changes account passwords.
```

### Linux — Credential Patterns in /etc
```
Found 15 matches in /etc (47 files searched):

=== /etc/cloud/cloud.cfg ===
42:   - set_passwords
96:     lock_passwd: True

=== /etc/debconf.conf ===
14: World-readable, and accepts everything but passwords.
18: Reject-Type: password

[Results truncated at 15 matches]
```

## Features

- **Regex support**: Full Go regexp syntax (Perl-compatible)
- **Extension filtering**: Search only specific file types
- **Binary skip**: Automatically skips 40+ binary extensions (.exe, .dll, .zip, .png, etc.)
- **Hidden dir skip**: Skips `.git`, `node_modules`, `__pycache__`, and hidden directories
- **Context lines**: Show lines before each match for surrounding context
- **Size limit**: Skip oversized files to avoid memory issues

## OPSEC Considerations

- File I/O operations — reading files generates filesystem access events
- Large directory scans may trigger file access monitoring / EDR alerts
- Use `extensions` filter and `max_depth` to limit scan scope
- Use `max_results` to cap output size

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery
- **T1552.001** — Unsecured Credentials: Credentials In Files
