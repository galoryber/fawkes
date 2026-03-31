+++
title = "amcache"
chapter = false
weight = 156
hidden = false
+++

## Summary

Query and clean forensic execution artifacts. Targets platform-specific artifacts that record program execution:

- **Windows**: Shimcache (AppCompatCache) — registry-based execution history
- **Linux**: recently-used.xbel (GTK/GNOME), thumbnail cache, GNOME Tracker database
- **macOS**: Recent items, KnowledgeC database, quarantine events, shared file lists

Cleaning these artifacts removes evidence of tool execution, complementing other anti-forensics commands (prefetch, usn-jrnl, eventlog, history-scrub).

{{% notice warning %}}Delete/clear actions may require elevated privileges (Windows: HKLM registry write, macOS: some artifacts require root){{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | query | Action: `query`, `search`, `delete`, or `clear` |
| name | No | | Executable name or path pattern (case-insensitive substring match) |
| count | No | 50 | Maximum entries to display (for query action) |

### Actions

- **query** — List forensic artifact entries (Windows: Shimcache paths/timestamps; Linux: recently-used files + artifact sizes; macOS: artifact inventory)
- **search** — Search for specific name or path pattern (Windows/Linux: substring match; macOS: matches artifact labels/paths)
- **delete** — Remove matching entries (Windows: rewrite Shimcache; Linux: filter recently-used.xbel; macOS: remove matching artifact files)
- **clear** — Remove all forensic artifacts across all tracked locations

## Usage

```
# View recent forensic artifact entries
amcache -action query

# View more entries
amcache -action query -count 200

# Search for specific executable/file
amcache -action search -name fawkes

# Delete entries matching a pattern
amcache -action delete -name fawkes.exe

# Clear all forensic artifacts
amcache -action clear
```

### Platform-Specific Behavior

**Windows:**
- Queries/modifies Shimcache (AppCompatCache) in the registry
- Supports all 4 actions with entry-level granularity

**Linux:**
- `query` shows recently-used.xbel entries + thumbnail/tracker artifact sizes
- `search`/`delete` operate on recently-used.xbel entries
- `clear` removes recently-used entries, thumbnail cache, and GNOME Tracker DB

**macOS:**
- `query` inventories recent items, KnowledgeC, quarantine events, shared file lists
- `search`/`delete` match against artifact labels/paths (binary format artifacts)
- `clear` removes all detected forensic artifact files

## Output Format

The `query` and `search` actions return a JSON array rendered as a sortable table via browser script:
```json
[
  {
    "index": 0,
    "last_modified": "2025-01-15 14:30:22",
    "path": "\\??\\C:\\Windows\\System32\\cmd.exe"
  }
]
```

The browser script highlights suspicious executables (powershell, cmd, wscript, cscript, mshta) in orange. Other actions (delete, clear) return plain text status messages.

## Operational Notes

- **Windows — Shimcache vs Amcache**: This command targets the Shimcache (AppCompatCache registry value), which is the in-memory execution tracker. The Amcache.hve hive file is a separate artifact.
- **Windows — Shimcache persistence**: The Shimcache is written to the registry on system shutdown. Changes take effect immediately in the registry but the in-memory cache may still contain entries until the next reboot.
- **Windows — Format support**: Automatically detects Windows 10/11 format (signature `10ts`/`0x30747331`) and Windows 8/8.1 format.
- **Linux — recently-used.xbel**: GTK/GNOME recently used file tracker. Located at `~/.local/share/recently-used.xbel` (XDG) or `~/.recently-used.xbel` (legacy). XML format with entry-level granularity.
- **Linux — Thumbnail cache**: Located at `~/.cache/thumbnails/`. Contains PNG thumbnails that reveal which files have been viewed.
- **Linux — GNOME Tracker**: Located at `~/.cache/tracker3/` (Tracker 3.x) or `~/.local/share/tracker/` (Tracker 2.x). Indexes file metadata.
- **macOS — KnowledgeC**: Application usage tracking database at `~/Library/Application Support/Knowledge/knowledgeC.db`.
- **macOS — Quarantine events**: Records downloaded files at `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`.
- **Combine with other anti-forensics**: Use alongside `prefetch -action clear`, `usn-jrnl -action delete`, `auditpol -action stealth`, `eventlog -action clear`, and `history-scrub -action clear-all` for comprehensive evidence removal.

## MITRE ATT&CK Mapping

- **T1070.004** — Indicator Removal: File Deletion
