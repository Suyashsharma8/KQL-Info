Human operators play a significant part in planning, managing, and executing cyber-attacks. During each phase of their operations, they learn and adapt by observing the victims’ networks and leveraging intelligence and social engineering. One of the most common tools human operators use is Remote Desktop Protocol (RDP), which gives attackers not only control, but also Graphical User Interface (GUI) visibility on remote computers. As RDP is such a popular tool in human operated attacks, it allows defenders to use the RDP context as a strong incriminator of suspicious activities. And therefore, detect Indicators of Compromise (IOCs) and act on them.
Reference: https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/detect-compromised-rdp-sessions-with-microsoft-defender-for/ba-p/4201003. This modified query provides a broader detection capability for registry modifications, focusing on changes made during remote sessions. By capturing a wider range of registry keys and values, you can better identify potentially suspicious activities that could indicate a compromised system or unauthorized access. You can further customize the query based on specific registry keys or values that are relevant to your organization's security posture. Note: DWORD registry value is a way for Windows to store and manage numerical settings in the registry, often used to enable or disable features.

```kql
DeviceRegistryEvents
| where Timestamp >= ago(7d)  // Adjust the time frame as needed
| where RegistryKey has "SOFTWARE\\Policies\\Microsoft\\Windows" // Broader key path
| where RegistryValueType == "Dword" // Focus on DWORD values
| where RegistryValueData in (0, 1) // Look for values that could indicate changes (enabled/disabled)
| where IsInitiatingProcessRemoteSession == true // Focus on remote sessions
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueType, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
