This query detects delete + recreate of same s3 bucket name within 1 hour. This is a simple detection for potential hijack exposure.

```kql
let Deletes = AWSCloudTrail
| where EventName == "DeleteBucket"
| extend BucketName = tostring(parse_json(RequestParameters).bucketName)
| project BucketName, DeleteTime=TimeGenerated;
let Creates = AWSCloudTrail
| where EventName == "CreateBucket"
| extend BucketName = tostring(parse_json(RequestParameters).bucketName)
| extend Creator = UserIdentityArn
| project BucketName, CreateTime=TimeGenerated, Creator;
Deletes
| join kind=inner Creates on BucketName
| where CreateTime between (DeleteTime .. datetime_add('hour', 1, DeleteTime))

