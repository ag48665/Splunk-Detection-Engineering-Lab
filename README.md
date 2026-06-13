# Windows Forensics Lab

## Overview

This project demonstrates a basic Windows Forensics investigation using Splunk Enterprise and Sysmon telemetry.

The objective is to analyze endpoint activity, investigate process execution, review network activity, identify account discovery behavior, analyze file creation events, and document findings using a structured forensic workflow.

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

## Investigation Objectives

- Investigate PowerShell activity
- Review command shell execution
- Identify account discovery techniques
- Analyze network connections
- Review file creation events
- Build a forensic timeline
- Document findings

---

# Investigation Steps

## 1. PowerShell Activity Analysis

### Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "powershell.exe"
```

### Purpose

Review PowerShell execution activity and identify the process responsible for launching PowerShell.

### Evidence

![PowerShell Detection](screenshots/powershell_detection.png)

---

## 2. Command Shell Activity Analysis

### Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "cmd.exe"
```

### Purpose

Review command-line activity that may indicate manual execution or post-exploitation behavior.

### Evidence

![Command Shell Detection](screenshots/command_shell_detection.png)

---

## 3. Account Discovery Investigation

### Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
("whoami.exe" OR "net.exe")
```

### Purpose

Identify account enumeration and discovery techniques commonly used during attacker reconnaissance.

### MITRE ATT&CK

| Technique | Name |
|------------|------|
| T1087 | Account Discovery |

### Evidence

![Account Discovery](screenshots/account_discovery_detection.png)

---

## 4. Network Connection Analysis

### Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "<EventID>3</EventID>"
```

### Purpose

Review Sysmon Network Connection events and identify outbound communications.

### MITRE ATT&CK

| Technique | Name |
|------------|------|
| T1049 | System Network Connections Discovery |

### Evidence

![Network Connections](screenshots/network_connection_detection.png)

---

## 5. File Creation Analysis

### Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "<EventID>11</EventID>"
```

### Purpose

Review Sysmon File Creation events to identify dropped files and potential staging activity.

### Evidence

![File Creation](screenshots/sysmon_eventid11_file_creation.png)

---

# Timeline

| Step | Activity |
|--------|----------|
| T1 | PowerShell activity reviewed |
| T2 | Command shell activity reviewed |
| T3 | Account discovery activity identified |
| T4 | Network connection events analyzed |
| T5 | File creation events reviewed |

---

# Findings

- PowerShell execution activity was observed.
- Command-line execution activity was identified.
- Account discovery commands were present.
- Network connection events were reviewed.
- File creation events were analyzed.
- Sysmon provided detailed endpoint visibility across process, network, and file activity.

---

# Skills Demonstrated

- Windows Forensics
- Splunk SPL
- Sysmon Analysis
- Event Log Investigation
- Incident Investigation
- Threat Hunting
- Endpoint Monitoring
- MITRE ATT&CK Mapping
- Security Analysis

---

# Author

**Agata Gabara**

Cybersecurity Analyst | SOC Analyst | Threat Hunter

GitHub: https://github.com/ag48665

