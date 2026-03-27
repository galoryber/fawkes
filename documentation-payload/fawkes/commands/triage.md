+++
title = "triage"
chapter = false
weight = 190
hidden = false
+++

## Summary

Find high-value files for exfiltration across common locations. Scans platform-appropriate directories for documents, credentials, configuration files, or custom paths.

Cross-platform (Windows, Linux, macOS).

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | all | Triage mode: `all` (docs+creds+configs), `documents`, `credentials`, `configs`, `database`, `scripts`, `archives`, `mail`, `recent`, `custom` |
| path | For custom | - | Directory to scan when using `custom` action |
| hours | No | 24 | Time window in hours for `recent` action |
| max_size | No | 10485760 | Maximum file size in bytes (default 10MB) |
| max_files | No | 200 | Maximum number of files to return |

## Usage

### Scan all categories
```
triage
triage -action all
```

### Find documents only
```
triage -action documents
```

### Find credential files
```
triage -action credentials
```

### Find configuration files
```
triage -action configs
```

### Find recently modified files
```
triage -action recent
triage -action recent -hours 48
triage -action recent -hours 1
```

### Find database files
```
triage -action database
```

### Find scripts
```
triage -action scripts
```

### Find archives/backups
```
triage -action archives
```

### Find email files
```
triage -action mail
```

### Scan custom directory
```
triage -action custom -path /opt/webapp
```

### Limit results
```
triage -action all -max_files 50 -max_size 5242880
```

## Categories

### Documents
Office files (.doc, .docx, .xls, .xlsx, .ppt, .pptx, .pdf), text files (.txt, .md, .log, .csv, .rtf), OpenDocument formats (.odt, .ods, .odp).

**Search paths:** Desktop, Documents, Downloads, OneDrive (Windows), home directory (Linux).

### Credentials
Key files (.kdbx, .kdb, .key, .pem, .pfx, .p12, .ppk), SSH keys (id_rsa, id_ed25519), VPN configs (.ovpn), credential stores (credentials.json, .netrc, .pgpass), web configs (web.config, wp-config.php), Java keystores (.jks, .keystore).

**Search paths:** ~/.ssh, ~/.aws, ~/.azure, ~/.gcloud, ~/.gnupg, ~/.config, AppData (Windows), /etc, /opt, /var/www (Linux).

### Configs
Configuration files (.conf, .cfg, .ini, .yaml, .yml, .json, .xml, .properties, .env, .toml).

**Search paths:** /etc, ~/.config, ~/.kube, ~/.docker, ~/.aws, ~/.azure, ProgramData (Windows).

### Database
Database files (.db, .sqlite, .sqlite3, .mdb, .accdb, .ldf, .mdf, .sdf, .bak).

**Search paths:** Home directory, /var/lib, /opt, /var/www, /srv, /tmp (Linux). Home, Documents, AppData, C:\inetpub, C:\ProgramData (Windows).

### Scripts
Script files (.py, .sh, .bash, .ps1, .psm1, .bat, .cmd, .vbs, .js, .rb, .pl, .php, .lua, .go, .rs).

**Search paths:** Home directory, /opt, /usr/local/bin, /var/www, /srv (Linux). Documents, Desktop, Downloads, C:\Scripts, C:\Tools (Windows).

### Archives
Archive files (.zip, .7z, .rar, .tar, .gz, .tgz, .bz2, .xz, .cab, .iso, .dmg).

**Search paths:** Home directory, /tmp, /var/backups, /opt (Linux). Documents, Desktop, Downloads, C:\Backups, C:\Temp (Windows).

### Mail
Email files (.pst, .ost, .eml, .msg, .mbox, .emlx, .dbx, .nsf).

**Search paths:** Home directory, ~/.thunderbird, ~/.local/share/evolution/mail, /var/mail, /var/spool/mail (Linux). Outlook Files, AppData/Local/Microsoft/Outlook, Thunderbird Profiles, Documents, Desktop (Windows). Library/Mail, Library/Thunderbird/Profiles, Documents (macOS).

### Recent
Files modified within the specified time window (default: 24 hours). Automatically categorizes files as cred, doc, config, script, log, database, or other based on name/extension. Results sorted by modification time (newest first). Skips noise directories (.cache, node_modules, .git, __pycache__, etc.).

**Search paths:** Home directory, /tmp, /var/log, /opt (Linux), Desktop/Documents/Downloads/AppData (Windows).

## Output Format

Returns JSON array of file results, rendered by a browser script into a color-coded sortable table.

### JSON Structure
```json
[
  {"path": "/home/user/Documents/report.pdf", "size": 1048576, "modified": "2026-02-28 08:00", "category": "doc"},
  {"path": "/home/user/.ssh/id_rsa", "size": 2048, "modified": "2026-01-15 12:30", "category": "cred"},
  {"path": "/etc/nginx/nginx.conf", "size": 4096, "modified": "2026-02-20 14:00", "category": "config"}
]
```

### Browser Script Rendering

The browser script renders results as a color-coded sortable table with human-readable file sizes:
- **Red** rows indicate **credential files** (keys, passwords, keystores)
- **Orange** rows indicate **configuration files** (.conf, .yaml, .env, etc.)
- **Blue** rows indicate **document files** (.pdf, .docx, .xlsx, etc.)

Columns: Path, Size (human-readable), Modified, Category.

Use `download` to exfiltrate individual files identified by triage.

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery
- **T1005** — Data from Local System
