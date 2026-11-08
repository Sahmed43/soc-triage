# Case Study: Investigating a Synthetic Multi-Stage SOC Alert Cluster

**Lab type:** Synthetic offline event correlation  
**Investigation date in sample data:** October 15, 2026 (UTC)  
**Tooling:** Python 3, Windows SecurityEvent-style JSONL, MITRE ATT&CK, SQLite casebook, Markdown/JSON reporting  
**Important:** No real enterprise environment, network, user, or adversary was involved.

## Security question

Could a detection engineer correlate isolated Windows security events into a useful analyst workload, without treating every log event as proof of an incident?

## Setup

The lab consumes 18 synthetic records, including failed Windows logons (4625), a successful logon (4624), a process creation event (4688), a privileged group addition event (4732), and an audit log clearing event (1102).

Test IP addresses use documentation-only address ranges (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`). Fake hosts use `lab.example`.

## Reproducible results

```bash
soc-triage scan \
  --input sample_data/events.jsonl \
  --config config/detections.json \
  --json reports/findings.json \
  --markdown reports/situation-report.md \
  --db reports/cases.sqlite
```

A tested demo generates six findings:

| Alert | Severity | Why it fires | Analyst follow-up |
| --- | --- | --- | --- |
| Repeated failed authentication | Medium | 6 failed logons for one account from one IP | Verify legitimate user activity and lockout patterns |
| Successful logon after failures | High | Successful event follows a rapid failed-logon sequence | Check session details and follow-on activity |
| Possible password spraying | High | 5 different accounts see failure from one IP | Confirm shared infrastructure isn't the explanation |
| PowerShell with encoded argument | High | Process command line uses encoded-command option | Review process tree, parent, and approved scripts |
| Privileged group modification | High | Event identifies a privileged group change | Verify the access request and operator |
| Audit log cleared | High | Event ID 1102 is present | Review maintenance approvals and alternate log sources |

These do **not** establish a coordinated intrusion; they illustrate hypotheses that an analyst would investigate and correlate. Detections can generate false positives.

## Example incident triage notes

A SOC analyst could open the high-severity successful-logon finding and document:

1. **Alert:** A synthetic account had six failures followed by a successful login from the same synthetic IP.
2. **Hypothesis:** Password guessing (T1110), though normal user error remains plausible.
3. **Evidence to request:** Authentication logs, account risk/MFA records, endpoint telemetry, and the owner's confirmation.
4. **Decision:** Keep the case `investigating` until facts confirm or disprove compromise.
5. **Containment:** Never revoke sessions or disable accounts solely on this demonstration; obtain organizational approval if production evidence warrants action.
6. **Improvements:** Correlate device identifiers, authentication method and successful-login source context to reduce false positives.

## Engineering tradeoffs to discuss in interviews

- **Recall vs precision:** Low thresholds are easier to demonstrate, but can create noisy alerts in a real domain.
- **Schema fidelity:** Native Sentinel exports may have sparse fields; mapping requires connector-specific validation.
- **Event identity:** Batch-based case IDs are reproducible for an unchanged file, but not stable across expanded windows.
- **Protection of evidence:** JSON reports may include sensitive command lines or identifiers; production logging needs access restrictions and retention controls.
- **Attack mapping:** ATT&CK IDs represent possible techniques, not attribution or certainty.

## Follow-up improvements

Record real Sentinel query validation in an authorized lab, add rule tuning metrics and false-positive test sets, and write a mock escalation email based on the report. These would demonstrate a progression from coding to operational SOC ownership.
