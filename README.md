# SOC Detection Rules

Detection rules for SOC monitoring based on MITRE ATT&CK.

## Tools

* Sysmon
* ELK Stack
* Windows Event Logs
* MITRE ATT&CK

## Detection Use Cases

* PowerShell Execution Detection (T1059.001)
* Suspicious Process Creation
* Credential Dumping Detection
* Data Exfiltration Detection

## Example Rule

### PowerShell Execution

Event ID: 1
Image: powershell.exe
CommandLine: suspicious flags

MITRE: T1059.001

## SIEM Query Example

Kibana Query:
process.name : "powershell.exe"
