# Enabling Entra ID Logs
 
This Bicep template configures **Entra ID Logs (Diagnostic Settings)** at the tenant scope, forwarding Entra ID logs to a Log Analytics Workspace and Microsoft Sentinel.
 
---
 
## Overview
 
The template deploys a `microsoft.aadiam/diagnosticSettings` resource that enables a comprehensive set of AAD log categories and streams them to a specified Log Analytics Workspace. This is commonly used to feed security logs into **Microsoft Sentinel** for monitoring, alerting, and threat detection.
 
---
 
## Prerequisites
 
- Azure CLI or PowerShell with Bicep support
- Permissions to deploy at **tenant scope** (`Global Administrator`)
- An existing Log Analytics Workspace
 
---
 
## Parameters
 
| Parameter | Type | Default | Description |
|---|---|---|---|
| `lawResourceId` | `string` | *(pre-set)* | Resource ID of the target Log Analytics Workspace |
| `enableSignInLogs` | `bool` | `true` | Interactive user sign-in logs |
| `enableAuditLogs` | `bool` | `true` | Directory audit logs |
| `enableNonInteractiveUserSignInLogs` | `bool` | `true` | Non-interactive sign-in logs |
| `enableServicePrincipalSignInLogs` | `bool` | `true` | Service principal sign-in logs |
| `enableManagedIdentitySignInLogs` | `bool` | `true` | Managed identity sign-in logs |
| `enableProvisioningLogs` | `bool` | `true` | Provisioning activity logs |
| `enableADFSSignInLogs` | `bool` | `true` | AD FS sign-in logs |
| `enableRiskyUsersLogs` | `bool` | `true` | Risky users logs |
| `enableUserRiskEvents` | `bool` | `true` | User risk event logs |
| `enableRiskyServicePrincipalLogs` | `bool` | `true` | Risky service principal logs |
| `enableServicePrincipalRiskEvents` | `bool` | `true` | Service principal risk event logs |
| `enableNetworkAccessTrafficLogs` | `bool` | `true` | Network access traffic logs |
 
---
 
## Deployment
 
### 1. Update the Log Analytics Workspace Resource ID
 
Before deploying, update the `lawResourceId` parameter in the template (or pass it at deploy time) to point to your own workspace:
 
```bicep
param lawResourceId string = '/subscriptions/<subscription-id>/resourceGroups/<rg-name>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>'
```
 
### 2. Deploy via PowerShell - Service Principal
 
```powershell
$tenantId = "your-tenant-id"
$appId = "your-service-principal-id"
$secret = "your-secret-value"

$secureSecret = ConvertTo-SecureString $secret -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($appId, $secureSecret)

Connect-AzAccount -ServicePrincipal -TenantId $tenantId -Credential $credential -Verbose

New-AzTenantDeployment -Location "your-location" -TemplateFile "C:\saved-location\file-name.bicep"
```
 
---
 
## Log Categories
 
The following AAD log categories are configured by this template:
 
| Category | Description |
|---|---|
| `SignInLogs` | Interactive user sign-ins |
| `AuditLogs` | Changes to directory objects |
| `NonInteractiveUserSignInLogs` | Client-initiated sign-ins without user interaction |
| `ServicePrincipalSignInLogs` | App and service principal authentications |
| `ManagedIdentitySignInLogs` | Managed identity authentications |
| `ProvisioningLogs` | User/group provisioning activity |
| `ADFSSignInLogs` | Sign-ins via Active Directory Federation Services |
| `RiskyUsers` | Users flagged as at-risk by Identity Protection |
| `UserRiskEvents` | Risk detections associated with user accounts |
| `RiskyServicePrincipals` | Service principals flagged as at-risk |
| `ServicePrincipalRiskEvents` | Risk detections associated with service principals |
| `NetworkAccessTrafficLogs` | Microsoft Entra network access traffic |
 
---
 
## Notes
 
- All log categories are **enabled by default**. Set any parameter to `false` to disable a specific category.
- The `targetScope` is set to `'tenant'`, which requires elevated permissions to deploy.
- This template is idempotent — redeploying will update the existing diagnostic settings resource in place.
