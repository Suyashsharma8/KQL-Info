
This query is designed to detect configuration changes made to enable access via storage account keys
```kql
AzureActivity 
| where OperationNameValue has "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE" 
| where ActivityStatusValue has "Success" 
| extend allowSharedKeyAccess = parse_json(tostring(parse_json(tostring(parse_json(Properties).responseBody)).properties)).allowSharedKeyAccess 
| where allowSharedKeyAccess == "true"
