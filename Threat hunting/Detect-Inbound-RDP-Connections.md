DeviceNetworkEvents
| where ActionType == "ListeningConnectionCreated" and LocalPort == 3389
| extend LocalIPIsPrivate = ipv4_is_private(LocalIP)
| where LocalIPIsPrivate == true
| summarize 
    LastSeen=max(Timestamp), 
    Count=count(), 
    IPs=make_set(LocalIP),
    Processes=make_set(InitiatingProcessFileName)
    by DeviceName, LocalPort
| order by Count desc, LastSeen desc
