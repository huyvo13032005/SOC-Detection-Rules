# Encoded PowerShell Detection

## MITRE ATT&CK

T1059.001 - PowerShell

## Description

Detect PowerShell commands executed using encoded payload.

## Log Source

Sysmon Event ID 1 - Process Creation

## Detection Logic

Look for encoded flags:

* -enc
* -encodedcommand

## Kibana Query

process.name : "powershell.exe" AND
process.command_line : ("-enc" OR "-encodedcommand")

## Investigation Steps

1. Decode Base64 command
2. Identify payload
3. Check parent process
4. Check user context
5. Correlate with network activity

## Severity

High
