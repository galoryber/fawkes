+++
title = "gpp-password"
chapter = false
weight = 119
hidden = false
+++

## Summary

Searches SYSVOL on a domain controller for Group Policy Preferences (GPP) XML files containing encrypted passwords (`cpassword` attributes) and decrypts them using the well-known AES-256 key published by Microsoft (MS14-025).

GPP allowed administrators to set local account passwords, scheduled task credentials, service accounts, and drive mappings via Group Policy. The passwords were encrypted with a fixed AES-256 key that Microsoft published in MSDN documentation. While MS14-025 (May 2014) patched the ability to *create* new GPP with passwords, existing XML files may still contain decryptable credentials.

This command is cross-platform — it connects to SYSVOL via SMB.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| server   | Yes      |         | Domain controller hostname or IP |
| username | Yes      |         | Username (user@domain or DOMAIN\user) |
| password | Yes      |         | Password for SMB authentication |
| domain   | No       |         | Domain name (optional if included in username) |
| port     | No       | 445     | SMB port |

## Usage

```
# Search SYSVOL for GPP passwords
gpp-password -server dc01.domain.local -username user@domain.local -password Pass123

# Search by IP
gpp-password -server 192.168.1.10 -username DOMAIN\user -password Pass123
```

### Searched Files

The command searches for these GPP XML files in all policy directories under SYSVOL:

| File | GPP Feature |
|------|-------------|
| Groups.xml | Local user/group management |
| ScheduledTasks.xml | Scheduled task credentials |
| Services.xml | Windows service account passwords |
| DataSources.xml | ODBC data source credentials |
| Drives.xml | Mapped drive credentials |

### OPSEC Notes

- Creates an SMB connection to the target DC's SYSVOL share
- Reads XML files from the Policies directories
- Does not modify any files
- Modern environments (post-2014) should not have GPP passwords, but legacy configurations may persist

## MITRE ATT&CK Mapping

- **T1552.006** - Unsecured Credentials: Group Policy Preferences
