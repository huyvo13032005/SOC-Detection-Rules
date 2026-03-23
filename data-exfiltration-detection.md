# Data Exfiltration Detection

## MITRE ATT&CK

T1041 - Exfiltration Over Command and Control Channel

## Description

Detect suspicious data exfiltration using PowerShell or command-line tools.

## Log Source

Sysmon Event ID 3 - Network Connection

## Suspicious Indicators

* Large outbound connections
* PowerShell making network connections
* Unknown external IPs

## Detection Logic

Monitor PowerShell network activity

## Kibana Query

process.name : "powershell.exe" AND
network.direction : "outbound"

## Investigation Steps

1. Identify destination IP
2. Check command line
3. Verify user activity
4. Check data transfer size
5. Correlate with file access

## Severity

High
