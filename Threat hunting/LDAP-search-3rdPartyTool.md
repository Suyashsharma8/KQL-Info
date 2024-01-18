LDAP requests from 3rd part tools / LDAP activities that initiated by enumeration tools, possibly unwanted and suspicious
```kql
let tools = dynamic(["pingcastle", "sharp", "blood", "sharphound", "bloodhound" ]);
DeviceEvents
//| where DeviceName contains "nlarcl13600.sec.intra"
| where ActionType == "LdapSearch"
| where ProcessCommandLine has_any (tools) or InitiatingProcessCommandLine has_any (tools) or FileName has_any (tools) or InitiatingProcessFileName has_any (tools)
| extend ParsedFields=parse_json(AdditionalFields)
 | extend AttributeList = ParsedFields.AttributeList
 | extend ScopeOfSearch = ParsedFields.ScopeOfSearch
 | extend SearchFilter = ParsedFields.SearchFilter
 | extend DistinguishName = ParsedFields.DistinguishedName
 //| project ParsedFields, AttributeList, ScopeOfSearch, SearchFilter, DistinguishName
