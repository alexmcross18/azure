# Self Assigned Role in Azure

## What this detection is looking for

This detection looks for a user account assigning themself a role in Azure. It does this by querying the AuditLogs table, searching for successful added to role operations only, filters out admins adding roles to users and removes any blank rows (removing some false positives).

## Why this detection is useful

Role assignments in Entra ID control what a user can access across your entire Azure environment. A self-assigned privileged role (e.g. Global Administrator) could give an attacker complete control of your tenant.

## MITRE ATT&CK Mapping

Tactic - **Privelege Escalation**

Technique - **T1078.004 - Valid Accounts**

```kql
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
// Catch both HKLM and HKCU Run keys for full coverage
| where RegistryKey has_any (
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
)
// Flag entries pointing to suspicious locations
| where RegistryValueData has_any (
    "\\AppData\\",
    "\\Temp\\",
    "\\ProgramData\\",
    "powershell",
    "cmd.exe",
    "wscript",
    "mshta"
)
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RegistryKey,
    RegistryValueName,
    RegistryValueData
```
