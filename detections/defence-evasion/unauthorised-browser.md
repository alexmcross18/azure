# Unauthorised Web Browser Detected

## What this detection looks for
This detection identifies the execution of unauthorised or non-standard web browsers (e.g. Brave, Opera, Vivaldi) on corporate endpoints by monitoring process creation events.

These browsers may fall outside of approved software baselines and are not always subject to enterprise security controls such as hardening policies, monitoring, or extension management.

## Why we should use this detection

The use of unauthorised browsers can indicate attempts to bypass security controls or operate outside of monitored environments. These browsers may be unpatched, misconfigured, or lack enterprise security tooling, increasing exposure to browser-based exploits and vulnerabilities.

Additionally, attackers may leverage non-standard browsers to evade detection, reduce visibility, or access corporate resources from unmanaged contexts.

Detection Logic (KQL):

```kql
let browsers = dynamic(["brave.exe", "opera.exe", "vivaldi.exe"]);      // Creates a list of browsers you want to be alerted on.

let browserInUse = (DeviceProcessEvents      // Creates a function that searches the DeviceProcessEvents table for the browsers in the previously created list.
| where ActionType == "ProcessCreated"
| where FileName has_any (browsers) or ProcessCommandLine has_any (browsers)
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine);

let browserInUse2 = (DeviceEvents      // Creates a function that seaches the DeviceEvents table for the browsers in the previously created list.
| where FileName has_any (browsers) or ProcessCommandLine has_any (browsers)
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine);
union browserInUse, browserInUse2      // Calls both the previously created functions to search for the browsers.
```
