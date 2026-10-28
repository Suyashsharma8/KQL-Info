If the storage account configuration 'Allow Blob anonymous access' is set to enabled and a container is created with anonymous read access, a threat actor could access the storage contents from the internet without any authorization.This query helps identify successful configuration changes to enable anonymous access 

```kql
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue =~ "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"
| where ActivityStatusValue =~ "Success"
| extend Props = parse_json(tostring(Properties))
| extend RequestBody = parse_json(tostring(Props["requestbody"])),
         ResponseBody = parse_json(tostring(Props["responseBody"]))
| extend RequestValue = tostring(RequestBody.properties.allowBlobPublicAccess),
         ResponseValue = tostring(ResponseBody.properties.allowBlobPublicAccess)
| extend AllowBlobPublicAccess = case(
    isnotempty(RequestValue), RequestValue,
    isnotempty(ResponseValue), ResponseValue,
    ""
)
| where tolower(AllowBlobPublicAccess) == "true"

