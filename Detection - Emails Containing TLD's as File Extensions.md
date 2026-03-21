# Emails Containing TLD's as File Extensions

## What this detection is looking for

This detection looks for emails with links/URLS's that have certain extensions at the end that may make it appear to be a file. 

## Why this detection is useful

Criminals are using ".zip" domains, which are top-level-domains (TLD's) that mimic the names of big tech companies.

These domains blur the line between a file and a website, making it harder to tell the difference.

For example, an email with an attachment called "sheet1.zip" could be a scam created by criminals, directing a user to a malicious URL when clicked/opened.

```kql
let knownSenders = dynamic([      // Creates a list of known/legit senders that may do this.
"knownSender1@domain.com",
"knownSender2@domain.com",
"knownSender3@domain.com"
]);
EmailUrlInfo
| where UrlDomain endswith ".zip" or UrlDomain endswith ".mov"
| join EmailEvents on NetworkMessageId
| where SenderFromAddress !in (knownSenders)
| where DeliveryAction =="Delivered"
| where DeliveryLocation != "On-premises/external
| extend SPF = split(AuthenticationDetails, ',')[0],
    DKIM = split(AuthenticationDetails, ',')[1],
    DMARC = split(AuthenticationDetails, ',')[2]
| project TimeGenerated, Url, Subject, UrlDomain, UrlLocation, SenderFromAddress, SenderMailAddress, RecipientEmailAddress, SenderIPv4, DeliveryLocation, SPF, DKIM, DMARC
```
