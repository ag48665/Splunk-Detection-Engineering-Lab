# Splunk Detection Engineering Lab

## Overview

This project demonstrates the creation and validation of security detections using Splunk Enterprise and Sysmon telemetry.

The objective is to develop detection logic, validate Sysmon event visibility, map activity to MITRE ATT&CK techniques, and document detection engineering workflows commonly used by SOC Analysts and Detection Engineers.

---

## Environment

| Component | Details |
|-----------|---------|
| SIEM | Splunk Enterprise 10.4 |
| Endpoint | Windows 11 |
| Telemetry | Sysmon |
| Log Source | Microsoft-Windows-Sysmon/Operational |
| Framework | MITRE ATT&CK |

---

## Detection Use Cases

- PowerShell Execution Detection
- Command Shell Activity Detection
- Account Discovery Detection
- Network Connection Monitoring
- File Creation Monitoring

---

# Detection 1 – PowerShell Execution

## Objective

Detect PowerShell execution activity using Sysmon Process Creation events.

### SPL Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "powershell.exe"