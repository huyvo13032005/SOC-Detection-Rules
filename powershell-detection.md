# PowerShell Execution Detection

## MITRE ATT&CK

T1059.001 - PowerShell

## Description

Detect suspicious PowerShell execution using Sysmon Event ID 1.

## Log Source

Sysmon Event ID 1 - Process Creation

## Detection Logic

* Process Name: powershell.exe
* Suspicious Flags:

  * -enc
  * -encodedcommand
  * -nop
  * -w hidden

## Kibana Query

process.name : "powershell.exe" AND
process.command_line : ("-enc" OR "-encodedcommand" OR "-nop")

## Investigation Steps

1. Check parent process
2. Analyze command line
3. Verify user context
4. Check network connections
5. Correlate with other alerts

## False Positives

* Legitimate admin scripts
* Automation tools

## Severity

Medium → High
