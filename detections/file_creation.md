# File Creation Detection

## Description

Monitor file creation activity using Sysmon Event ID 11.

## MITRE ATT&CK

T1074 – Data Staged
T1105 – Ingress Tool Transfer

## SPL Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "<EventID>11</EventID>"
```

## Expected Result

Returns file creation events that may indicate payload staging, downloads, or suspicious file operations.
