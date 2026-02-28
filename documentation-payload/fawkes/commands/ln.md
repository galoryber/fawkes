+++
title = "ln"
chapter = false
weight = 215
hidden = false
+++

## Summary

Create symbolic or hard links. Symbolic links create a reference to another file path (can point to non-existent paths). Hard links create an additional directory entry for the same file data (both names reference the same inode).

Useful for symlink attacks, DLL side-loading setups, creating backup references, and file system manipulation.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| target | Yes | | Path to the existing file or directory |
| link | Yes | | Path for the new link to create |
| symbolic | No | false | Create a symbolic link instead of a hard link |
| force | No | false | Remove existing file/symlink at link path before creating |

## Usage

Create a hard link:
```
ln -target /tmp/original.txt -link /tmp/hardlink.txt
```

Create a symbolic link:
```
ln -target /etc/passwd -link /tmp/passwd_link -symbolic true
```

Force-replace an existing symlink:
```
ln -target /tmp/new_target -link /tmp/existing_link -symbolic true -force true
```

Windows symbolic link:
```
ln -target C:\Windows\System32\calc.exe -link C:\temp\calc.exe -symbolic true
```

## Notes

- **Hard links** require the target to exist and must be on the same filesystem. Both names share the same data — deleting one doesn't affect the other.
- **Symbolic links** can point to non-existent paths (dangling symlinks) and can cross filesystem boundaries.
- On Windows, symbolic links may require elevated privileges or Developer Mode enabled.

## MITRE ATT&CK Mapping

- **T1036** — Masquerading
