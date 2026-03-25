# Successful sign-in from Unusual Location.

## What this detection is looking for

This detection identifies successful sign-ins from locations, specifically CountryCode's that aren't included in a specific watchlist.

## Why this detection is useful

This can catch attackers who have gained access to a compromised account as soon as they sign-in. This gives the SOC team a good head start to start investigating and containing the threat before they have a chance to attack. 

## Dependencies

This detection relies on the SignInLogs diagnostic setting being enabled in Entra ID and parsed into the Log Analytics Workspace that your Sentinel instance is attached to.

As well as a watchlist being created in Sentinel, with a column called "CountryCode" and updated with the relevant information including the SearchKey being the CountryCode.

## False Positive Guidance

The investigating SOC should start with ruling out the below:

- VPN usage
- Working from abroad

## MITRE ATT&CK Mapping

Tactic - **Initial Access**

Technique - **T1078 - Valid Accounts**

## Tuning

Add all the CountryCode's you recognise as legit locations to the watchlist.

```kql
// Define a list of known/approved country codes from the Sentinel watchlist "yourWatchlistName".
let knownLocations = (_GetWatchlist('yourWatchlistName') | project CountryCode);
// Build a lookup of each user's last successful sign-in from a known location in the last 30 days.
let lastKnownLocation = SigninLogs
| where ResultSignature == "SUCCESS"
| where Location in (yourWatchlistName)
| where TimeGenerated > ago(30d)
| summarize LastKnownSignInTime = max(TimeGenerated) by UserPrincipalName, LastKnownLocation = Location;
SigninLogs
// Only include sign-ins from locations NOT in the known locations watchlist.
| where Location !in (yourWatchlistName)
// Only include successful sign-ins.
| where ResultSignature == "SUCCESS"
// Return only the relevant columns.
| project
    TimeGenerated,
    Identity,
    UserDisplayName,
    UserPrincipalName,
    UserType,
    Location,
    AppDisplayName,
    AuthenticationRequirement,
    ClientAppUsed,
    ConditionalAccessStatus,
    IsInteractive,
    IPAddress,
    LocationDetails
| order by TimeGenerated desc 
```
