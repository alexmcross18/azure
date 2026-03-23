# Emails Containing TLD's as File Extensions

## What this detection is looking for

This detection looks for emails with links/URLS's that have certain extensions at the end that may make it appear to be a file. 

## Why this detection is useful

Criminals are using ".zip" domains, which are top-level-domains (TLD's) that mimic the names of big tech companies.

These domains blur the line between a file and a website, making it harder to tell the difference.

For example, an email with an attachment called "sheet1.zip" could be a scam created by criminals, directing a user to a malicious URL when clicked/opened.

```kql
// Creates a list of known/legit senders that may do this.
let knownSenders = dynamic([
"knownSender1@domain.com",
"knownSender2@domain.com",
"knownSender3@domain.com"
]);
// Creates a list of abusable TLDs.
let suspiciousTLDs = dynamic([
    ".zip", ".mov", ".cfd", ".quest", ".cam", ".fin", ".llc", ".vip", ".gq", ".tk"
]);
// Searches the EmailUrlInfo table for emails that contain domains that end in one of the suspiciousTLDs.
EmailUrlInfo
| where UrlDomain has_any (suspiciousTLDs)
// Enriches the filtered EmailUrlInfo results with email metadata from EmailEvents, joined on the NetworkMessageId.
| join kind=leftouter EmailEvents on NetworkMessageId
// Enrich results with click data from UrlClickEvents to determine if and when a recipient clicked the suspicious URL on NetworkMessageId.
| join kind=leftouter (
    UrlClickEvents
    | project NetworkMessageId, TimeGenerated, ClickAction=ActionType, ClickUser=AccountUpn, IsClickedThrough, ThreatTypes, ClickIP=IPAddress
) on NetworkMessageId
// Excludes known senders.
| where SenderFromAddress !in (knownSenders)
// Only delivered mail.
| where DeliveryAction == "Delivered"
// Removes duplicates from on-prem Exchange server.
| where DeliveryLocation != "On-premises/external"
// Parses SPF, DKIM and DMARC into their own rows to make them easier to see.
| extend SPF = split(AuthenticationDetails, ',')[0],
         DKIM = split(AuthenticationDetails, ',')[1],
         DMARC = split(AuthenticationDetails, ',')[2]
// Count how many recipients got the same message.
| join kind=leftouter (
    EmailEvents
    | summarize RecipientCount = dcount(RecipientEmailAddress) by NetworkMessageId
) on NetworkMessageId
// Final output
| project TimeGenerated, Subject, Url, UrlDomain, UrlLocation, SenderFromAddress, RecipientEmailAddress, RecipientCount,  SenderIPv4,  DeliveryLocation, ClickAction,  SPF, DKIM, DMARC
| order by TimeGenerated desc 
```
