# PowerShell Execution Detection

## Description

Detect PowerShell execution activity using Sysmon Process Creation events.

## MITRE ATT&CK

T1059.001 – PowerShell

## SPL Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "powershell.exe"
```

## Expected Result

Returns PowerShell process execution events collected by Sysmon.
