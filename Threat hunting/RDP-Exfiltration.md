
This KQL query detects possible RDP-based file transfer by identifying file access on redirected drives (`\\tsclient`) during a remote session.

```kql
DeviceFileEvents
| where isnotempty(InitiatingProcessRemoteSessionIP)
| where FolderPath startswith @"\\tsclient"
| where isnotempty(RequestAccountName)
      and RequestAccountName !in~ ("<add accounts to exclude>")
| project
    Timestamp,
    RemoteIP = InitiatingProcessRemoteSessionIP,
    External_Device = InitiatingProcessRemoteSessionDeviceName,
    DeviceId,
    Connected_to = DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessVersionInfoFileDescription,
    RequestAccountName,
    RequestAccountDomain,
    IsInitiatingProcessRemoteSession,
    InitiatingProcessSessionId,
    ReportId
```


