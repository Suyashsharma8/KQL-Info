This query is to review the advisory from Proofpoint about cybercriminal threat activity leveraging Cloudflare Tunnels to deliver malware. SOC added the IoC's in Misp and reviewed the logs for the last 30 days and found no hits.
Reference: https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats
The following KQL can be used for detection.
```kql
UrlClickEvents
| where Timestamp > ago(30d)
| extend domain = tostring(parse_url(Url).Host)
| where domain endswith ".trycloudflare.com"
| join EmailEvents on NetworkMessageId
| project Timestamp, Url, RecipientEmailAddress, SenderMailFromAddress, SenderFromAddress, Subject, AttachmentCount, UrlCount 
