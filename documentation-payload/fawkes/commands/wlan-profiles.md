+++
title = "wlan-profiles"
chapter = false
weight = 197
hidden = false
+++

## Summary

Recover saved WiFi network profiles and credentials. Windows uses the native WLAN API to extract plaintext keys. Linux reads NetworkManager, wpa_supplicant, and iwd configuration files. macOS queries the Keychain for AirPort network passwords.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| name | No | | Filter by SSID name (substring match) |

## Usage

List all saved WiFi profiles:
```
wlan-profiles
```

Search for a specific network:
```
wlan-profiles -name CorpWiFi
```

## MITRE ATT&CK Mapping

- **T1555** — Credentials from Password Stores
