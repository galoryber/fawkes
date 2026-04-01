+++
title = "masquerade"
chapter = false
weight = 220
hidden = false
+++

## Summary

File masquerading — copy or rename files with deceptive names to evade detection. Supports multiple techniques for making malicious files appear benign. Cross-platform with OS-appropriate process name suggestions.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| source | Yes | — | Path to the file to masquerade |
| technique | Yes | — | Masquerade technique (see below) |
| disguise | No | varies | Technique-specific disguise value |
| in_place | No | false | Rename in-place (true) or create a copy (false) |

### Techniques

| Technique | Description | Example |
|-----------|-------------|---------|
| double_ext | Double extension — file appears as one type but is another | `payload.exe` → `document.pdf.exe` |
| rtlo | Right-to-Left Override Unicode character reverses display | `payload‮txt.exe` displays as `payloadexe.txt` |
| space | Trailing spaces hide the real extension | `payload.txt                              .exe` |
| process | Match legitimate OS process names | `payload.exe` → `svchost.exe` |
| match_ext | Change file extension to benign type | `payload.exe` → `payload.txt` |

## Usage

```
# Double extension — looks like a PDF
masquerade -source C:\payload.exe -technique double_ext -disguise report.pdf

# RtL override — filename appears reversed in Explorer
masquerade -source /tmp/payload -technique rtlo -disguise txt

# Space padding — real extension hidden by whitespace
masquerade -source C:\payload.exe -technique space -disguise docx

# Match a Windows system process name
masquerade -source C:\payload.exe -technique process -disguise svchost

# Match a Linux daemon name
masquerade -source /tmp/payload -technique process -disguise sshd

# Rename in-place instead of copying
masquerade -source C:\payload.exe -technique match_ext -disguise txt -in_place true
```

## MITRE ATT&CK Mapping

- **T1036** — Masquerading
- **T1036.005** — Match Legitimate Name or Location
- **T1036.007** — Double File Extension
