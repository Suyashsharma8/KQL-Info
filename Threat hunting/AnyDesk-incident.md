This hunt is used to detect AnyDesk breach incident. AnyDesk announced hackers breached its production servers, reset passwords Reference: https://www.bleepingcomputer.com/news/security/anydesk-says-hackers-breached-its-production-servers-reset-passwords/

``kql
DeviceNetworkEvents
| where Timestamp >= ago(30d)
|where InitiatingProcessVersionInfoCompanyName == "philandro Software GmbH" 
and InitiatingProcessVersionInfoProductName == "AnyDesk"
| where ActionType == "ConnectionSuccess"
|project Timestamp,ActionType,DeviceName, RemoteIP,RemoteUrl, InitiatingProcessVersionInfoCompanyName, InitiatingProcessVersionInfoFileDescription, InitiatingProcessVersionInfoProductVersion
