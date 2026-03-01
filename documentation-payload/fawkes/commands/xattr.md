+++
title = "xattr"
chapter = false
weight = 210
hidden = false
+++

{{% notice info %}}Linux/macOS Only{{% /notice %}}

## Summary

Manage extended file attributes — list, get, set, and delete. Unix complement to the Windows `ads` command for hiding data in file metadata. Extended attributes are key-value pairs attached to files that are not visible through normal file listing.

Common use cases: hiding payloads or configuration data, storing exfiltration staging data, and creating covert channels via file metadata.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | list | Action: list, get, set, delete |
| path | Yes | | Target file path |
| name | Conditional | | Attribute name (e.g., `user.secret`). Required for get, set, delete |
| value | Conditional | | Value to set. Required for set action |
| hex | No | false | Treat value as hex-encoded binary data |

## Usage

List all extended attributes on a file:
```
xattr -path /tmp/file.txt
```

Set a text attribute:
```
xattr -action set -path /tmp/file.txt -name user.hidden -value "secret data"
```

Set binary data via hex encoding:
```
xattr -action set -path /tmp/file.txt -name user.payload -value 4d5a90 -hex true
```

Read an attribute:
```
xattr -action get -path /tmp/file.txt -name user.hidden
```

Read with hex dump:
```
xattr -action get -path /tmp/file.txt -name user.payload -hex true
```

Delete an attribute:
```
xattr -action delete -path /tmp/file.txt -name user.hidden
```

## OPSEC Considerations

- Extended attributes are preserved during file copies on the same filesystem
- The `user.*` namespace is accessible to any user who owns the file
- Some backup tools and forensic tools enumerate xattrs — consider cleanup after use
- On macOS, `xattr -l <file>` from the terminal will reveal all extended attributes

## MITRE ATT&CK Mapping

- **T1564.004** — Hide Artifacts: NTFS File Attributes (applies to both ADS and xattr)
