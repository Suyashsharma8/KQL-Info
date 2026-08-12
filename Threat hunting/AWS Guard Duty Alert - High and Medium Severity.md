AWS Guard Duty Alert - High and Medium Severity

```kql
let Watchlist=_GetWatchlist('watch_list');	
// https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html 	
AWSGuardDuty 	
// Parse the finding	
// https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html 	
// Example: "ThreatPurpose:ResourceTypeAffected/ThreatFamilyName.DetectionMechanism!Artifact"	
| extend findingTokens = split(ActivityType, ":")	
| extend ThreatPurpose=findingTokens[0], findingTokens=split(findingTokens[1], "/")	
| extend ResourceTypeAffected=findingTokens[0], findingTokens= split(findingTokens[1], ".")	
| extend ThreatFamilyName=findingTokens[0], findingTokens=split(findingTokens[1], "!")	
| extend DetectionMechanism=findingTokens[0], Artifact=findingTokens[1]	
// Assign severity level	
// https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html#guardduty_findings-severity	
| extend Severity = 	
    case (	
      Severity >= 7.0, "High",	
      Severity between (4.0 .. 6.9), "Medium",	
      Severity between (1.0 .. 3.9), "Low",	
      "Unknown"	
    )	
// Pull out any available resource details we can extract entities from. These may not exist in the alert.	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_Resource.html 	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_AccessKeyDetails.html 	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_RdsDbUserDetails.html 	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_KubernetesDetails.html 	
| extend AccessKeyDetails=ResourceDetails.accessKeyDetails	
| extend RdsDbUserDetails=ResourceDetails.rdsDbUserDetails	
| extend KubernetesDetails=ResourceDetails.kubernetesDetails	
// Pull out any available action details we can extract entities from. These may not exist in the alert.	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_Action.html 	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_AwsApiCallAction.html 	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_KubernetesApiCallAction.html 	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_NetworkConnectionAction.html 	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_RdsLoginAttemptAction.html 	
| extend ServiceAction = 	
    case(	
      isnotempty(ServiceDetails.action.awsApiCallAction), ServiceDetails.action.awsApiCallAction,	
      isnotempty(ServiceDetails.action.kubernetesApiCallAction), ServiceDetails.action.kubernetesApiCallAction,	
      isnotempty(ServiceDetails.action.networkConnectionAction), ServiceDetails.action.networkConnectionAction,	
      isnotempty(ServiceDetails.action.rdsLoginAttemptAction), ServiceDetails.action.rdsLoginAttemptAction,	
      dynamic(null)	
    )	
// The IPv4 remote address of the connection	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_RemoteIpDetails.html 	
// or	
// The IP of the Kubernetes API caller and the IPs of any proxies or load balancers between the caller and the API endpoint 	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_KubernetesApiCallAction.html 	
| extend RemoteIpAddress = 	
    coalesce(	
      tostring(ServiceAction.remoteIpDetails.ipAddressV4),	
      tostring(parse_json(ServiceAction.sourceIPs)[0])	
    )	
// The IPv4 local address of the connection	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_LocalIpDetails.html 	
| extend LocalIpAddress = ServiceAction.localIpDetails.ipAddressV4	
// The AWS account ID of the remote API caller.	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_AwsApiCallAction.html 	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_RemoteAccountDetails.html 	
| extend RemoteAWSAccountId = ServiceAction.remoteAccountDetails.accountId	
// The IAM access key details (user information) of a user that engaged in the activity that prompted GuardDuty to generate a finding	
// https://docs.aws.amazon.com/guardduty/latest/APIReference/API_AccessKeyDetails.html 	
| extend AccountUpn = 	
    case(	
      AccessKeyDetails.userType == "IAMUser", AccessKeyDetails.userName,	
      AccessKeyDetails.userType == "AssumedRole", split(AccessKeyDetails.principalId, ":", 1)[0],	
      isnotempty(RdsDbUserDetails.user), RdsDbUserDetails.user,	
      isnotempty(KubernetesDetails.kubernetesUserDetails.username), KubernetesDetails.kubernetesUserDetails.username,	
      ""	
    )	
| extend AccountName = split(AccountUpn, "@", 0)[0]	
| extend UPNSuffix = split(AccountUpn, "@", 1)[0]	
// Clean up the output	
| extend GuardDutyDetails =	
    bag_pack( 	
      "DetectorId", ServiceDetails.detectorId,	
      "Partition", Partition,	
      "Region", Region	
    )	
| extend FindingLink = 	
    iff(	
      isnotempty(Region) and isnotempty(Id),	
      strcat("https://", Region, ".console.aws.amazon.com/guardduty/home?region=", Region, "#/findings?fId=", Id),	
      ""	
    )	
| extend FindingLinkDescription = 	
    iff(	
      isnotempty(FindingLink),	
      strcat("Link to GuardDuty finding (AWS): ", FindingLink),	
      ""	
    )
| project-rename 
    FindingArn=Arn,
    FindingId=Id,
    AWSAccountId=AccountId
|where Severity in ("High", "Medium") 
    //|where AWSAccountId == "**************" //filter AWS accounts
    |extend ThreatFamilyName=tostring(ThreatFamilyName)
    |lookup Watchlist on $left.AWSAccountId==$right.AWSAccountId and $left.ThreatFamilyName==$right.ThreatFamily
    |where isempty(Note)
    |where not(
    ThreatFamilyName =~ "InstanceCredentialExfiltration"
    and DetectionMechanism =~ "OutsideAWS"
    and RemoteIpAddress == "*******"
    )
    // Known Rancher administrative activity
| where not(
    ResourceTypeAffected =~ "Kubernetes"
    and AccountUpn contains "cattle"
    and ThreatFamilyName =~ "RoleBindingCreated"
)
// Known Rancher workload behavior
| where not(
    ResourceTypeAffected =~ "Kubernetes"
    and AccountUpn contains "cattle"
    and ThreatFamilyName =~ "ContainerWithSensitiveMount"
)
// Known Rancher operational activity
| where not(
    ResourceTypeAffected =~ "Kubernetes"
    and AccountUpn contains "<service-accounts>"
    and ThreatFamilyName =~ "ExecInKubeSystemPod"
)
// Known Jenkins Buildah CI/CD activity
| where not(
    ResourceTypeAffected =~ "Kubernetes"
    and AccountUpn contains "jenkins"
    and ThreatFamilyName =~ "PrivilegedContainer"
)
| where not(
    ResourceTypeAffected =~ "Kubernetes"
    and ThreatFamilyName =~ "AnomalousBehavior"
    and (
        AccountUpn has "system:serviceaccount:******"
        or AccountUpn has "system:serviceaccount:*******"
    )
)
// Known Kubernetes administrator activity
| where not(
    AWSAccountId == "****************"
    and ResourceTypeAffected =~ "Kubernetes"
    and ThreatFamilyName =~ "AnomalousBehavior"
    and DetectionMechanism in~ ( "ExecInPod", "SecretsAccessed", "RoleBindingCreated")
    and AccountName == "************"
)
| project-away 
    ActivityType, 
    findingTokens,
    Partition,
    Region, 
    SchemaVersion,
    TimeGenerated,
    Type		
```
