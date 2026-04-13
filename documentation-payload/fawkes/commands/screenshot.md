+++
title = "screenshot"
chapter = false
weight = 103
hidden = false
+++

## Summary

Capture a screenshot of the current desktop session, or continuously record screenshots at configurable intervals. Uploads as PNG to Mythic. Cross-platform.

On **Windows**, uses GDI (GetDC/BitBlt) to capture the virtual screen across all monitors.

On **Linux**, auto-detects the display server (X11 via `DISPLAY`, Wayland via `WAYLAND_DISPLAY`) and tries available screenshot tools in order:
- **X11**: `import` (ImageMagick), `scrot`, `gnome-screenshot`, `xfce4-screenshooter`
- **Wayland**: `grim`, `gnome-screenshot`

On **macOS**, uses the `screencapture` CLI tool for native screen capture.

## Arguments

Argument | Required | Description
---------|----------|------------
action | No | `single` (default) for one screenshot, `record` for continuous capture
interval | No | Seconds between captures (record mode, default: 5)
duration | No | Total recording duration in seconds (record mode, default: 60, max: 600)
max_frames | No | Maximum number of frames to capture (record mode, default: 100, max: 1000)

## Usage

Single screenshot (backward compatible — no arguments needed):
```
screenshot
```

Continuous recording — 5-second intervals for 60 seconds:
```
screenshot -action record -interval 5 -duration 60
```

Record with limits:
```
screenshot -action record -interval 2 -duration 120 -max_frames 50
```

Stop recording early with `jobkill`.

## MITRE ATT&CK Mapping

- **T1113** — Screen Capture
