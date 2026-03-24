# SOC Detection Workflow

## Workflow

Attack Simulation
↓
Log Generation
↓
Sysmon Collection
↓
ELK Ingestion
↓
Detection Rule Triggered
↓
Alert Generated
↓
SOC Analyst Investigation
↓
MITRE ATT&CK Mapping
↓
Incident Response

## Description

1. Attacker executes malicious command
2. Sysmon logs process creation
3. Logs forwarded to ELK Stack
4. Detection rule matches behavior
5. SIEM generates alert
6. SOC analyst investigates
7. Map activity to MITRE ATT&CK
8. Respond to incident

## Tools Used

* Sysmon
* ELK Stack
* Kibana
* MITRE ATT&CK
