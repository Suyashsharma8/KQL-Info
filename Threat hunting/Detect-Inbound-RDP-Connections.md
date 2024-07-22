This query detects inbound RDP connections on internal company devices. It filters for listening connections on port 3389 (RDP) on private IP addresses.
```kusto
DeviceNetworkEvents
| where ActionType == "ListeningConnectionCreated" and LocalPort == 3389
| extend LocalIPIsPrivate = ipv4_is_private(LocalIP)
| where LocalIPIsPrivate == true // 'True' ensures we're only looking at internal network endpoints, 'False' for local IP is public.
| summarize 
    LastSeen=max(Timestamp), 
    Count=count(), 
    IPs=make_set(LocalIP),
    Processes=make_set(InitiatingProcessFileName)
    by DeviceName, LocalPort
| order by Count desc, LastSeen desc
