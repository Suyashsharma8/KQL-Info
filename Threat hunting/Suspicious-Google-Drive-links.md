This query is used to detect malicious google document links present in the emails that are sent inbound. This is taken reference from https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries. 
Malicious actors might use Google Documents to host and distribute phishing pages or malicious links. They can craft convincing-looking documents that include malicious links.

```kql
EmailUrlInfo
| where Url startswith "https://docs.google.com/document/" 
| join kind=inner (EmailEvents 
| where EmailDirection == "Inbound" 
| where InternetMessageId matches regex "\\<\\w{38,42}\\@") on NetworkMessageId
| join kind=inner (UrlClickEvents 
| where Url startswith "https://docs.google.com/document/") on NetworkMessageId

