# Command Shell Execution Detection

## Description

Detect execution of Windows Command Prompt (cmd.exe) using Sysmon Process Creation events.

## MITRE ATT&CK

T1059.003 – Windows Command Shell

## SPL Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "cmd.exe"
```

## Expected Result

Returns Sysmon process creation events related to cmd.exe execution.
