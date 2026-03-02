+++
title = "watch-dir"
chapter = false
weight = 210
hidden = false
+++

## Summary

Monitor a directory for file system changes in real-time. Detects new files, modified files, and deleted files using configurable polling. Supports glob pattern filtering and optional MD5 hash-based change detection.

Cross-platform (Windows, Linux, macOS).

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | Yes | - | Directory to monitor |
| interval | No | 5 | Poll interval in seconds |
| duration | No | 0 | Maximum monitoring duration in seconds (0 = run until stopped via `jobkill`) |
| depth | No | 3 | Maximum subdirectory depth to scan |
| pattern | No | - | Glob pattern to filter monitored files (e.g., `*.docx`) |
| hash | No | false | Use MD5 hashing for change detection (catches in-place edits with same size/mtime) |

## Usage

### Monitor a user's Desktop for 5 minutes
```
watch-dir -path C:\Users\target\Desktop -duration 300
```

### Watch for document changes with pattern filter
```
watch-dir -path /home/user/Documents -pattern *.xlsx -duration 600
```

### Continuous monitoring until stopped
```
watch-dir -path /tmp/staging -interval 10
```
Stop with `jobkill` when finished.

### Deep scan with hash detection
```
watch-dir -path C:\Users\target\Downloads -depth 5 -hash true -duration 300
```

## Change Detection

### Default mode (size + mtime)
Files are detected as modified if their size or modification time changes between polls. This is fast and sufficient for most scenarios.

### Hash mode (MD5)
When `hash` is enabled, each file's MD5 is computed on every poll. This catches in-place edits where the file size and modification time remain unchanged (e.g., overwriting with same-length content). Slower on large directories.

### Event types
- **CREATED** — New file appeared since the last poll
- **MODIFIED** — Existing file changed (size, mtime, or content hash)
- **DELETED** — File was removed since the last poll

## Output Format

```
Directory Watch Report: C:\Users\target\Desktop
Duration: 5m0s | Interval: 5s | Depth: 3
Changes: 3 total (1 created, 1 modified, 1 deleted)
--------------------------------------------------------------------------------
[14:30:15] CREATED    secret_report.pdf  (size: 245760)
[14:31:20] MODIFIED   budget.xlsx  (size: 8192 → 12288)
[14:32:05] DELETED    temp_notes.txt
```

## Operational Notes

- Runs as a long-running task. Use `jobkill` to stop if no `duration` is set.
- Poll interval controls the trade-off between detection latency and CPU/disk usage.
- On large directories, increase the interval and decrease depth to reduce overhead.
- Hash mode reads every file on every poll — use selectively on smaller directories.

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery
- **T1119** — Automated Collection
