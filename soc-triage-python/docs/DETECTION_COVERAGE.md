# Detection coverage and input assumptions

| Rule ID | Detection | Windows event IDs | MITRE ATT&CK | Primary input fields |
| --- | --- | --- | --- | --- |
| AUTH-001 | Repeated failed logons | 4625 | T1110.001 Password Guessing | time, user, source IP |
| AUTH-002 | Multi-account failures from one IP | 4625 | T1110.003 Password Spraying | time, distinct users, source IP |
| AUTH-003 | Successful logon after failures | 4625, 4624 | T1110 Brute Force | time, user, source IP |
| PROC-001 | Encoded PowerShell arguments | 4688, Sysmon 1, 4104* | T1059.001 PowerShell | process, command line |
| ID-001 | Privileged group modification | 4728, 4732, 4756 | T1098.007 Additional Local or Domain Groups | group name |
| LOG-001 | Windows security log cleared | 1102 | T1070.001 Clear Windows Event Logs | event ID |

*For Event ID 4104 the normalized command line must include a PowerShell process token and an encoded-argument pattern. This is an intentionally narrow illustrative rule, not complete PowerShell script-block analysis.

**Detection-quality note:** MITRE mappings indicate potential behaviors, not confirmed adversary activity. The tool must be tuned for the expected environment, legitimate change windows, complete telemetry, and historical false-positive rates.

More details: https://attack.mitre.org/techniques/
