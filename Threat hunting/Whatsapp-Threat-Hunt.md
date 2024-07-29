This Query can be used to detect the security issue in the whatsapp version for windows ( at the time of writing) that allows sending Python and PHP attachments which inturn executes without any warning when the recipient opens them.
Blog reference: https://www.bleepingcomputer.com/news/security/whatsapp-for-windows-lets-python-php-scripts-execute-with-no-warning/
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where InitiatingProcessFileName contains "WhatsApp.exe"
| where FileName endswith ".pyz" or FileName endswith ".pyzw" or FileName endswith ".php" or FileName endswith ".py"
```
The query can be modified to include wider extensions using regex and monitor file execution events:
```kql
DeviceProcessEvents
| where InitiatingProcessFileName contains "WhatsApp.exe"
| where FileName matches regex "\\.(pyz|pyzw|php|py|exe|dll|vbs|js|cmd|bat)$"
