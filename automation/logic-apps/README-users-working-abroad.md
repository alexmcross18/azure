# Abroad Working Users — Monthly Report
 
## Overview
 
A scheduled Azure Logic App that queries Microsoft Sentinel for successful sign-ins from outside the United Kingdom during the previous calendar month, exports the results as a CSV, and distributes them to a defined recipient list via email.
 
Built to reduce manual reporting effort and provide consistent visibility into foreign access activity across the environment.
 
---
 
## What It Does
 
1. **Triggers** on the 1st of every month at 01:00 AM (GMT Standard Time)
2. **Queries** the `SignInLogs` table in Microsoft Sentinel via Azure Monitor Logs
3. **Filters** for:
   - Sign-ins from outside Great Britain (`Location != "GB"`)
   - Successful authentications only (`ResultType == "0"`)
   - The previous full calendar month
4. **Enriches** each result with device context parsed from `DeviceDetail`:
   - Device ID, display name, OS, browser, trust type, compliance and management state
5. **Exports** the results to a CSV file
6. **Emails** the CSV as an attachment to the defined recipient list
7. **Alerts** recipients via a separate high-priority email if the Logic App run fails
 
---
 
## Flow Diagram
 
```
Recurrence Trigger (1st of month, 01:00 AM GMT)
        │
        ▼
Run KQL Query (SignInLogs — previous month, non-GB, successful)
        │
   ┌────┴────┐
Succeeded   Failed / Timed Out / Skipped
   │                    │
   ▼                    ▼
Create CSV        Send failure alert email
   │              (High importance)
   ▼
Send report email
(CSV attached)
```
 
---
 
## KQL Query
 
```kql
SignInLogs
| where TimeGenerated >= startofmonth(datetime_add('month',-1, now()))
| where TimeGenerated < startofmonth(now())
| where Location != "GB"
| where ResultType == "0"
| extend deviceDetails = parse_json(DeviceDetail)
| extend DeviceId = deviceDetails.deviceId,
         OperatingSystem = deviceDetails.operatingSystem,
         Browser = deviceDetails.browsers,
         DeviceDisplayName = deviceDetails.displayName,
         DeviceTrustType = deviceDetails.trustType,
         DeviceCompliant = deviceDetails.isCompliant,
         DeviceManaged = deviceDetails.isManaged
| project TimeGenerated, Identity, IPAddress, Location, UserPrincipalName,
          DeviceId, OperatingSystem, Browser, DeviceDisplayName,
          DeviceTrustType, DeviceCompliant, DeviceManaged
```
 
---
 
## Output
 
A CSV file (`abroadWorkingUsers.csv`) delivered via email containing:
 
| Field | Description |
|---|---|
| TimeGenerated | Timestamp of the sign-in event |
| Identity | Display name of the user |
| UserPrincipalName | UPN of the user |
| IPAddress | Source IP address |
| Location | Country of sign-in |
| DeviceId | Entra ID device identifier |
| DeviceDisplayName | Device name |
| OperatingSystem | OS of the device used |
| Browser | Browser used |
| DeviceTrustType | Trust type (e.g. Azure AD Joined, Hybrid) |
| DeviceCompliant | Whether the device was compliant at time of sign-in |
| DeviceManaged | Whether the device was managed at time of sign-in |
 
---
 
## Connections
 
| Connector | Purpose | Authentication |
|---|---|---|
| Azure Monitor Logs | Query Microsoft Sentinel / Log Analytics | Managed Identity |
| Outlook | Send report and failure alert emails | OAuth |
 
> **Note:** The Azure Monitor Logs connector uses a system-assigned managed identity. The identity must be granted **Log Analytics Reader** on the target Log Analytics Workspace and **Reader** at the subscription scope.
 
---
 
## Prerequisites
 
- Azure Logic App (Consumption or Standard)
- System-assigned managed identity enabled on the Logic App
- Log Analytics Workspace with `SignInLogs` ingested (requires Microsoft Entra ID diagnostic settings)
- Microsoft Sentinel enabled on the workspace
- Outlook connection authorised with a licensed Microsoft 365 account
 
---
 
## Deployment
 
The following files are included for deployment:
 
| File | Description |
|---|---|
| [users-working-abroad.json](./users-working-abroad.json) | Logic App workflow definition (portal export) |
| [ARM-template-users-working-abroad.json](./ARM-template-users-working-abroad.json) | ARM template for full deployment |
| [users-working-abroad.bicep](./users-working-abroad.bicep) | Bicep version of the ARM template |
 
Before deploying, update the following values in your chosen template:
 
- Subscription ID
- Resource group name
- Log Analytics Workspace name
- Email recipients in both `Send_an_email` actions
 
---
 
## Error Handling
 
If the KQL query fails, times out, or is skipped, a separate high-importance email is automatically sent to the recipient list prompting investigation. This ensures the absence of a report is never silently missed.
 
---
 
## Security Notes
 
- Subscription IDs and resource identifiers have been removed from this repository
- No credentials or secrets are stored in the workflow definition
- Authentication to Azure Monitor Logs is handled entirely via managed identity — no stored keys or passwords
