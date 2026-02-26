+++
title = "usn-jrnl"
chapter = false
weight = 108
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Query or delete the NTFS USN (Update Sequence Number) Change Journal. The USN Journal records every file operation on an NTFS volume — creates, deletes, renames, writes, security changes. Forensic analysts use it to reconstruct file activity timelines.

Actions:
- **query** — Show journal metadata (ID, USN range, size)
- **recent** — Show last 100 journal records with timestamps, filenames, and reasons
- **delete** — Destroy the entire journal (requires admin)

Deleting the journal destroys the forensic timeline for the volume. Deletion runs in the background and continues even across reboots. This is a high-impact anti-forensics action — the blue team loses visibility into all historical file operations.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action   | Yes      | query   | `query`, `recent`, or `delete` |
| volume   | No       | C:      | Volume letter to target |

## Usage

### Query journal metadata
```
usn-jrnl -action query
usn-jrnl -action query -volume D:
```

### View recent records
```
usn-jrnl -action recent
```

### Delete journal (anti-forensics)
```
usn-jrnl -action delete
usn-jrnl -action delete -volume D:
```

## MITRE ATT&CK Mapping

- T1070.004 — Indicator Removal: File Deletion
