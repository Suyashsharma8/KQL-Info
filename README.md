# KQL-Queries
This repo is to share KQL queries that i have learnt through research

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where DeviceName has "ComputerName"
| project Timestamp, ActionType, RemoteIP, RemotePort, RemoteUrl

