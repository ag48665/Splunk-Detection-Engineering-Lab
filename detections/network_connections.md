# Network Connection Detection

## Description

Monitor Sysmon network connection events.

## MITRE ATT&CK

T1049 – System Network Connections Discovery

## SPL Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "<EventID>3</EventID>"
```

## Expected Result

Returns outbound and inbound network connection events recorded by Sysmon.
