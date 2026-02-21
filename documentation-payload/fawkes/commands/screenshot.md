+++
title = "screenshot"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows and macOS
{{% /notice %}}

## Summary

Capture a screenshot of the current desktop session. Captures all monitors and uploads the result as a PNG image.

On **Windows**, uses GDI (GetDC/BitBlt) to capture the virtual screen across all monitors.

On **macOS**, uses the `screencapture` CLI tool for native screen capture.

### Arguments

No arguments.

## Usage
```
screenshot
```

## MITRE ATT&CK Mapping

- T1113
