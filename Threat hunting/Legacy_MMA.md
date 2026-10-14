```kql
DeviceTvmSoftwareInventory
| where SoftwareVendor contains "microsoft"
| where SoftwareName contains "monitoring agent"
```
