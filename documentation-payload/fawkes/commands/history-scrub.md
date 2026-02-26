+++
title = "history-scrub"
chapter = false
weight = 127
hidden = false
+++

## Summary

List or clear shell and application command history files. Cross-platform anti-forensics.

**Unix/macOS**: Targets `.bash_history`, `.zsh_history`, `.sh_history`, `.ksh_history`, `.fish_history`, plus application histories (`.python_history`, `.mysql_history`, `.psql_history`, `.sqlite_history`, `.lesshst`, `.viminfo`, `.wget-hsts`, `.node_repl_history`).

**Windows**: Targets PowerShell ConsoleHost history (`PSReadLine/ConsoleHost_history.txt`).

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | list | `list` = show history files, `clear` = clear shell history only, `clear-all` = clear all history including app-specific |
| user | No | current user | Target username to clear history for |

## Usage

### List history files
```
history-scrub
history-scrub -action list
```

### Clear shell history only
```
history-scrub -action clear
```

### Clear all history files (shell + application)
```
history-scrub -action clear-all
```

### Clear another user's history
```
history-scrub -action clear -user admin
```

### Example Output (list)
```
History Files Found
===================

Type           Lines         Size  Path
----           -----         ----  ----
bash           1247       42.1 KB  /home/user/.bash_history
zsh              89        3.2 KB  /home/user/.zsh_history
python           56        1.8 KB  /home/user/.python_history
mysql            23        0.9 KB  /home/user/.mysql_history

[4 history files, 1415 total lines, 48.0 KB total]
```

## MITRE ATT&CK Mapping

- T1070.003 -- Indicator Removal: Clear Command History
