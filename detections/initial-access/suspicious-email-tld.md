# Emails Containing TLD's as File Extensions

## What this detection is looking for

This detection identifies delivered emails containing URLs where the domain uses a suspicious top-level domain (TLD) such as .zip, .mov, .cfd, .quest, .cam, .fin, .llc, .vip, .gq, or .tk.

## Why this detection is useful

Attackers abuse TLDs that mimic common file extensions or are frequently used in malicious infrastructure. For example, a .zip or .mov domain can blur the line between a file and a website, tricking users into thinking they are opening a file attachment when they are actually visiting a malicious URL.
This detection goes beyond simply flagging suspicious URLs by also identifying:

Whether the email failed SPF, DKIM, and DMARC authentication checks, indicating possible spoofing.
Whether any recipient actually clicked the link.
How many recipients received the same email, helping identify mass phishing campaigns.

## Dependencies

This detection relies on Microsoft Defender for Office 365 and queries the following Advanced Hunting tables:

```EmailUrlInfo``` — URL data extracted from emails.

```EmailEvents``` — Email metadata including sender, recipient, and delivery info.

```UrlClickEvents``` — Click data from Safe Links.


Note: ```UrlClickEvents``` will only contain data if Safe Links is enabled in your Defender for Office 365 policy. Without it, click detection will not function.

## Tuning

Add trusted senders to the ```knownSenders``` allowlist at the top of the query to reduce false positives.

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
