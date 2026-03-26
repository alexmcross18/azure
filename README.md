# Security Detection Engineering & Automation (Azure)

> A reference library of KQL detection rules, Azure infrastructure templates, and security automation built on the Microsoft security stack. This is the engineering workbench behind the [CI/CD pipeline repo](https://github.com/your-username/infrastructure-and-detection-as-code-CI-CD-pipeline) — detections and infrastructure are developed and documented here before being operationalised there.

---

## What This Repository Is

This repo serves two purposes. First, it's a structured library of detection logic, each rule documented with its threat context, MITRE mapping, dependencies, and tuning guidance — the kind of detail that matters when you're handing a detection off to another analyst or justifying an alert to a stakeholder. Second, it's a collection of reusable Azure infrastructure templates for standing up and configuring the Azure and Sentinel stacks from scratch.

Nothing here requires a CI/CD pipeline to use. Every file is designed to be understandable, deployable, and adaptable on its own.

---

## Repository Structure

```
.
├── detections/
│   ├── defence-evasion/
│   │   ├── unauthorised-browsers.kql          # KQL: detect unauthorised browser execution
│   │   └── unauthorised-browser.md            # Docs: threat context, logic, MITRE mapping
│   ├── initial-access/
│   │   ├── suspicious-email-tld.kql           # KQL: emails with high-abuse TLD domains
│   │   ├── suspicious-email-tld.md            # Docs: dependencies, tuning, enrichment logic
│   │   ├── unusual-sign-in-location.kql       # KQL: sign-ins outside watchlist countries
│   │   └── unusual-sign-in-location.md        # Docs: watchlist setup, false positive guidance
│   ├── persistence/
│   │   ├── bunny-loader-malware.kql           # KQL: suspicious Run key registry writes
│   │   └── bunny-loader-malware.md            # Docs: malware context, MITRE mapping
│   └── privilege-escalation/
│       ├── user-assigned-role-to-themselves.kql  # KQL: self-assigned Entra ID role detection
│       └── user-assigned-role-to-themselves.md   # Docs: risk context, false positive tuning
│
├── infrastructure/
│   └── bicep/
│       ├── Log Analytics Workspace & Sentinel Deployment.bicep  # Bicep: deploy LAW + Sentinel
│       ├── Log Analytics Workspace & Sentinel Deployment.md     # Docs: deployment instructions
│       ├── Enabling Entra ID Logs.bicep                         # Bicep: configure AAD diagnostic settings
│       └── Enabling Entra ID Logs.md                            # Docs: log categories, deployment guide
│
└── automation/
    └── logic-apps/
        ├── users-working-abroad.json              # Logic App workflow definition (portal export)
        ├── ARM-template-users-working-abroad.json # ARM template for full deployment
        ├── users-working-abroad.bicep             # Bicep version of the ARM template
        └── README-users-working-abroad.md         # Docs: flow diagram, output schema, prerequisites
```

---

## Detection Rules (`/detections`)

Each detection is organised by MITRE ATT&CK tactic and ships as a pair: a `.kql` file containing the raw query, and a `.md` file documenting the threat context, dependencies, false positive guidance, and tuning approach. The detections in this folder have been ported into ARM templates and deployed via the CI/CD pipeline repo.

### Unauthorised Web Browsers
**Path:** `detections/defence-evasion/`  
**MITRE:** Defense Evasion — T1564

Detects the execution of browsers not approved by the organisation across three MDE tables — `DeviceProcessEvents`, `DeviceEvents`, and `DeviceNetworkEvents` — then unions the results and summarises by device and account, with first/last seen timestamps and an event count. Covering three tables closes the gap where a browser might be launched in a way that only appears in one of them.

Browsers to monitor are defined in a `let browsers = dynamic([...])` list at the top of the query. Replace the placeholder values with the executable names of browsers outside your approved baseline.

**Dependencies:** Microsoft Defender for Endpoint (MDE) — requires `DeviceProcessEvents`, `DeviceEvents`, and `DeviceNetworkEvents` tables.

---

### Emails Containing Suspicious TLDs
**Path:** `detections/initial-access/`  
**MITRE:** Initial Access

Searches `EmailUrlInfo` for delivered emails containing URLs whose domain ends in a high-abuse TLD (`.zip`, `.mov`, `.cfd`, `.quest`, `.cam`, `.fin`, `.llc`, `.vip`, `.gq`, `.tk`). Results are enriched with email metadata from `EmailEvents` and click data from `UrlClickEvents`, giving the analyst visibility into whether a recipient actually followed the link.

Additional enrichment includes SPF, DKIM, and DMARC parsed into discrete columns, a recipient count showing whether the same message was sent to multiple users, and a `knownSenders` exclusion list for false positive suppression.

**Dependencies:** Microsoft Defender for Office 365. `UrlClickEvents` data only populates if Safe Links is enabled in your Defender for Office 365 policy — without it, the click enrichment step returns no data.

---

### Sign-In from Unusual Location
**Path:** `detections/initial-access/`  
**MITRE:** Initial Access — T1078 (Valid Accounts)

Builds a dynamic lookup of each user's last known successful sign-in country from the past 30 days using a Sentinel Watchlist (`knownLocations`), then alerts on successful sign-ins from countries not present in that list. Surfaces authentication context for triage — MFA requirement, Conditional Access policy status, client app type, and full location detail.

**Dependencies:** `SignInLogs` diagnostic setting enabled in Entra ID and forwarded to the Log Analytics Workspace. A Sentinel Watchlist named `knownLocations` with a `CountryCode` column populated with approved country codes.

**False positive guidance:** Investigators should rule out VPN exit nodes and users legitimately working abroad before escalating.

---

### Bunny Loader Malware
**Path:** `detections/persistence/`  
**MITRE:** Persistence — T1547.001 (Boot or Logon Autostart: Registry Run Keys)

Monitors `DeviceRegistryEvents` for writes to Windows Run/RunOnce registry keys where the value data points to a suspicious execution path — `AppData`, `Temp`, `ProgramData`, or common LOLBin interpreters (`powershell`, `cmd.exe`, `wscript`, `mshta`). This pattern matches how Bunny Loader writes its persistence entry, but the broad path-based logic also catches other malware families that use the same technique.

**Dependencies:** Microsoft Defender for Endpoint — requires the `DeviceRegistryEvents` table.

---

### User Self-Assigned Role
**Path:** `detections/privilege-escalation/`  
**MITRE:** Privilege Escalation — T1078.004 (Valid Accounts: Cloud Accounts)

Queries `AuditLogs` for successful `Add member to role` operations where the initiating user and the target user share the same UPN — a strong indicator that a user has assigned themselves a privileged role without going through an administrator. Filters out events where either user field fails to parse (a common source of false positives in this table) and extracts the role name into its own column.

**Dependencies:** `AuditLogs` diagnostic setting enabled in Entra ID and forwarded to the Log Analytics Workspace.

---

## Infrastructure (`/infrastructure/bicep`)

### Log Analytics Workspace & Sentinel Deployment

**File:** `Log Analytics Workspace & Sentinel Deployment.bicep`

Deploys a Log Analytics Workspace and a Microsoft Sentinel instance in a single Bicep deployment. All key properties are parameterised — workspace name, retention period (30–730 days), and pricing tier. Outputs the workspace ID, workspace name, and Sentinel solution name to the deployment log.

**Deployment:**
```powershell
Connect-AzAccount
New-AzResourceGroupDeployment -ResourceGroupName 'yourResourceGroupName' -TemplateFile 'Log Analytics Workspace & Sentinel Deployment.bicep'
```
You will be prompted for `logAnalyticsWorkspaceName`, `retentionDays`, and `SKU` interactively.

---

### Enabling Entra ID Logs

**File:** `Enabling Entra ID Logs.bicep`

Configures Entra ID diagnostic settings at **tenant scope**, forwarding 12 log categories to a target Log Analytics Workspace. All categories are enabled by default and can be individually disabled by setting the corresponding parameter to `false`. Deploying at tenant scope requires Global Administrator permissions.

**Log categories configured:**

| Category | What it captures |
|---|---|
| `SignInLogs` | Interactive user sign-ins |
| `AuditLogs` | Directory object changes |
| `NonInteractiveUserSignInLogs` | Client-initiated sign-ins (no user interaction) |
| `ServicePrincipalSignInLogs` | App and service principal authentications |
| `ManagedIdentitySignInLogs` | Managed identity authentications |
| `ProvisioningLogs` | User/group provisioning activity |
| `ADFSSignInLogs` | Sign-ins via AD Federation Services |
| `RiskyUsers` | Users flagged at-risk by Identity Protection |
| `UserRiskEvents` | Risk detections on user accounts |
| `RiskyServicePrincipals` | Service principals flagged at-risk |
| `ServicePrincipalRiskEvents` | Risk detections on service principals |
| `NetworkAccessTrafficLogs` | Microsoft Entra network access traffic |

**Deployment:**
```powershell
Connect-AzAccount -TenantId 'your-tenant-id'
New-AzTenantDeployment -Location 'your-location' -TemplateFile 'Enabling Entra ID Logs.bicep'
```

---

## Automation (`/automation/logic-apps`)

### Abroad Working Users — Monthly Report

A scheduled Azure Logic App that runs on the 1st of every month at 01:00 AM (GMT) and produces a report of all successful sign-ins from outside Great Britain during the previous calendar month. Results are exported as a CSV and emailed to a defined recipient list. If the run fails, times out, or is skipped, a separate high-importance failure alert is sent automatically — ensuring the absence of a report is never silently missed.

**What the KQL query captures:**

```kql
SignInLogs
| where TimeGenerated >= startofmonth(datetime_add('month',-1, now()))
| where TimeGenerated < startofmonth(now())
| where Location != "GB"
| where ResultType == "0"
| extend deviceDetails = parse_json(DeviceDetail)
| project TimeGenerated, Identity, IPAddress, Location, UserPrincipalName,
          DeviceId, OperatingSystem, Browser, DeviceDisplayName,
          DeviceTrustType, DeviceCompliant, DeviceManaged
```

Each row in the CSV output includes device trust type, compliance state, and management state alongside the sign-in metadata — giving the reviewer enough context to distinguish a legitimate travelling employee on a managed device from an account compromise on an unknown machine.

**Logic App flow:**

```
Recurrence Trigger (1st of month, 01:00 GMT)
        │
        ▼
Run KQL Query against Log Analytics Workspace
        │
   ┌────┴────────────────────────┐
Succeeded                  Failed / Timed Out / Skipped
   │                                    │
   ▼                                    ▼
Create CSV table               Send high-priority failure alert email
   │
   ▼
Send report email with CSV attachment
```

**Authentication:** The Azure Monitor Logs connector uses a system-assigned managed identity — no stored keys or passwords. The managed identity requires **Log Analytics Reader** on the target workspace and **Reader** at subscription scope.

**Deployment files:**

| File | Use |
|---|---|
| `users-working-abroad.json` | Workflow definition only — import directly into an existing Logic App via the portal |
| `ARM-template-users-working-abroad.json` | Full ARM template — deploys the Logic App resource and its connections |
| `users-working-abroad.bicep` | Bicep equivalent of the ARM template |

Before deploying, update subscription ID, resource group name, Log Analytics Workspace name, and email recipients in your chosen template.

---

## Tech Stack

| Technology | Role |
|---|---|
| KQL | Detection query language across all Sentinel rules |
| Azure Bicep | Infrastructure as Code for LAW, Sentinel, and Entra ID log config |
| ARM Templates | Logic App and additional resource deployment |
| Microsoft Sentinel | Target SIEM for all detections |
| Microsoft Defender for Endpoint | Data source for endpoint-based detections |
| Microsoft Defender for Office 365 | Data source for email-based detections |
| Azure Logic Apps | Security automation and scheduled reporting |
| Microsoft Entra ID | Identity log source (SignInLogs, AuditLogs) |

---

## Relationship to the CI/CD Pipeline Repo

The resources have been kept as .bicep files (Log Analytics Workspace & Sentinel) and detections in this repository have been exported as ARM templates (policies, detections etc) and deployed into Azure and Sentinel via the [infrastructure-and-detection-as-code-CI-CD-pipeline](https://github.com/alexmcross18/infrastructure-and-detection-as-code-CI-CD-pipeline) repo. That repo handles automated deployment, version control, and multi-client targeting. This repo is where the resources and detection logic itself is written, documented, and maintained.

---

## About

This repository reflects the day-to-day work of building and maintaining security detection capability in a Microsoft-heavy environment — writing KQL, standing up infrastructure, and automating the manual processes that slow SOC teams down. It's actively maintained and will grow to include new detections, additional automation, and further infrastructure templates over time.
