This query will provide a report of many of the configurations for Defender ATP deployment.
```kql
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId in ('scid-91', 'scid-2000', 'scid-2001', 'scid-2002', 'scid-2003', 'scid-2010', 'scid-2011', 'scid-2012', 'scid-2013', 'scid-2014', 'scid-2016','scid-96')
| extend Test = case(
    ConfigurationId == "scid-2000", "SensorEnabled",
    ConfigurationId == "scid-2001", "SensorDataCollection",
    ConfigurationId == "scid-2002", "ImpairedCommunications",
    ConfigurationId == "scid-2003", "TamperProtection",
    ConfigurationId == "scid-2010", "AntivirusEnabled",
    ConfigurationId == "scid-2011", "AntivirusSignatureVersion",
    ConfigurationId == "scid-2012", "RealtimeProtection",
    ConfigurationId == "scid-91", "BehaviorMonitoring",
    ConfigurationId == "scid-96", "EnableNetworkProtection",
    ConfigurationId == "scid-2013", "PUAProtection",
    ConfigurationId == "scid-2014", "AntivirusReporting",
    ConfigurationId == "scid-2016", "CloudProtection",
    "N/A"),
    Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
| extend packed = pack(Test, Result)
| summarize Tests = make_bag(packed), DeviceName = any(DeviceName) by DeviceId, OSPlatform
| evaluate bag_unpack(Tests)
| project DeviceId, DeviceName,SensorEnabled, EnableNetworkProtection
| join kind=leftouter DeviceInfo on DeviceId
| summarize p1=dcount(DeviceId) by MachineGroup,DeviceType,DeviceName,SensorEnabled,EnableNetworkProtection
| where MachineGroup contains "*******" //Apply filters here to narrow search results
| where EnableNetworkProtection =="BAD"
| where DeviceType !="*******" //Apply filters here to narrow search results
| where SensorEnabled =="GOOD"
```
To get the details of the scid configured in your environment you can use the below query:
```kql
DeviceTvmSecureConfigurationAssessmentKB
| where ConfigurationId == "scid-2010"
| project ConfigurationId, ConfigurationName
