# Credential Dumping - LSASS Access Detection

## MITRE ATT&CK

T1003.001 - LSASS Memory

## Description

Detect suspicious access to LSASS process which may indicate credential dumping.

## Log Source

Sysmon Event ID 10 - Process Access

## Detection Logic

Look for processes accessing lsass.exe

## Suspicious Processes

* mimikatz.exe
* procdump.exe
* powershell.exe
* cmd.exe

## Kibana Query

target.process.name : "lsass.exe" AND
process.name : ("mimikatz.exe" OR "procdump.exe" OR "powershell.exe")

## Investigation Steps

1. Identify source process
2. Check command line
3. Verify user privileges
4. Look for lateral movement
5. Correlate with login events

## False Positives

* Antivirus software
* Backup tools

## Severity

Critical
