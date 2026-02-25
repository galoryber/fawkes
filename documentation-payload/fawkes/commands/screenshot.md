+++
title = "screenshot"
chapter = false
weight = 103
hidden = false
+++

## Summary

Capture a screenshot of the current desktop session and upload as PNG. Cross-platform.

On **Windows**, uses GDI (GetDC/BitBlt) to capture the virtual screen across all monitors.

On **Linux**, auto-detects the display server (X11 via `DISPLAY`, Wayland via `WAYLAND_DISPLAY`) and tries available screenshot tools in order:
- **X11**: `import` (ImageMagick), `scrot`, `gnome-screenshot`, `xfce4-screenshooter`
- **Wayland**: `grim`, `gnome-screenshot`

On **macOS**, uses the `screencapture` CLI tool for native screen capture.

### Arguments

No arguments.

## Usage
```
screenshot
```

## MITRE ATT&CK Mapping

- T1113
