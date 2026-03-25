# Self Assigned Role in Azure

## What this detection is looking for

This detection looks for a user account assigning themself a role in Azure. It does this by querying the AuditLogs table, searching for successful added to role operations only, filters out admins adding roles to users and removes any blank rows (removing some false positives).

## Why this detection is useful

Role assignments in Entra ID control what a user can access across your entire Azure environment. A self-assigned privileged role (e.g. Global Administrator) could give an attacker complete control of your tenant.

## MITRE ATT&CK Mapping

Tactic - **Privelege Escalation**

Technique - **T1078.004 - Valid Accounts**

```kql
AuditLogs
// Filter on only successful results.
| where Result == "success"
// Filter on only the operation of adding a member to a role.
| where OperationName == "Add member to role"
// Pulls out the initiating users UPN into it's own row.
| extend InitiatingUser = tostring(InitiatedBy.user.userPrincipalName)
// Pulls out the target users UPN into it's own row.
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
// Pulls out the role name into it's own row.
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
// Tunes for false positives in case the initiating user and target user fields fail to parse correctly and appear blank.
| where isnotempty(InitiatingUser) and isnotempty(TargetUser)
// Filters on only logs where the initiating user is the same as the target user.
| where InitiatingUser == TargetUser
// Projects relevant information.
| project TimeGenerated, OperationName, InitiatingUser, TargetUser, Result, RoleName
```
