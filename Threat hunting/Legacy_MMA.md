This query is for identifying devices with legacy MMA agents reference: https://learn.microsoft.com/en-us/defender-endpoint/update-agent-mma-windows
```kql
DeviceTvmSoftwareInventory
| where SoftwareVendor contains "microsoft"
| where SoftwareName contains "monitoring_agent"
```
