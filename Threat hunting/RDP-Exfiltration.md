

'''KQL
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
'''


