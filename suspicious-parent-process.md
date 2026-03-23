# Suspicious Parent Process Detection

## MITRE ATT&CK

T1059 - Command and Scripting Interpreter

## Description

Detect suspicious parent-child process relationships.

## Log Source

Sysmon Event ID 1 - Process Creation

## Suspicious Relationships

* winword.exe → powershell.exe
* excel.exe → cmd.exe
* outlook.exe → powershell.exe
* explorer.exe → powershell.exe (suspicious flags)

## Detection Logic

Look for Office applications spawning command shells.

## Kibana Query

parent.process.name : ("winword.exe" OR "excel.exe" OR "outlook.exe") AND
process.name : ("powershell.exe" OR "cmd.exe")

## Investigation Steps

1. Identify parent process
2. Check command line
3. Verify user activity
4. Look for macro execution
5. Check file origin

## Severity

High
