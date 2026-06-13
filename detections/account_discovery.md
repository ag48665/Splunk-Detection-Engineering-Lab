# Account Discovery Detection

## Description

Detect account enumeration activity commonly used during attacker reconnaissance.

## MITRE ATT&CK

T1087 – Account Discovery

## SPL Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
("whoami.exe" OR "net.exe")
```

## Expected Result

Returns account discovery commands executed on the endpoint.
