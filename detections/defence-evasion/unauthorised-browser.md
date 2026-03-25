# Unauthorised Web Browser Detected

## What this detection looks for
This detection identifies the execution of unauthorised or non-standard web browsers (e.g. Brave, Opera, Vivaldi) on corporate endpoints by monitoring process creation events.

These browsers may fall outside of approved software baselines and are not always subject to enterprise security controls such as hardening policies, monitoring, or extension management.

## Why we should use this detection

The use of unauthorised browsers can indicate attempts to bypass security controls or operate outside of monitored environments. These browsers may be unpatched, misconfigured, or lack enterprise security tooling, increasing exposure to browser-based exploits and vulnerabilities.

Additionally, attackers may leverage non-standard browsers to evade detection, reduce visibility, or access corporate resources from unmanaged contexts.

## MITRE ATT&CK Mapping

Tactic - **Defence-Evasion**

Technique - **T1548.002 - Bypass User Account Control**

Detection Logic (KQL):

```kql
// Creates a list of browsers you want to be alerted on.
let browsers = dynamic(["browser1.exe", "browser2.exe", "browser3.exe"]);
// Looks for a browser being opened in the DeviceProcessEvents table.
let BrowserProcessEvents = DeviceProcessEvents
| where FileName has_any (browsers)
    or ProcessCommandLine has_any (browsers)
| extend DetectionSource = "DeviceProcessEvents"
| project TimeGenerated, DeviceName, AccountName, DetectionSource, FileName, ProcessCommandLine, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine;
// Looks for a browser being opened in the DeviceEvents table.
let BrowserDeviceEvents = DeviceEvents
| where FileName has_any (browsers)
    or ProcessCommandLine has_any (browsers)
| extend DetectionSource = "DeviceEvents"
| project TimeGenerated, DeviceName, AccountName, DetectionSource, FileName, ProcessCommandLine, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine;
// Looks for a browser being opened in the DeviceNetworkEvents table.
let BrowserNetworkEvents = DeviceNetworkEvents
| where InitiatingProcessFileName has_any (browsers)
| extend DetectionSource = "DeviceNetworkEvents"
| project TimeGenerated, DeviceName, DetectionSource, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine;
// Summarizes the results.
BrowserProcessEvents
| union BrowserDeviceEvents
| union BrowserNetworkEvents
| summarize 
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    EventCount = count()
    by DeviceName, AccountName, FileName, SHA256, InitiatingProcessFileName
| sort by LastSeen desc
```
