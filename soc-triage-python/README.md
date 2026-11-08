# SOC Triage Lab — Python Security Monitoring & Incident Response

[![CI](https://img.shields.io/badge/tests-unittest-blue)](#automated-testing) ![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Lab](https://img.shields.io/badge/data-synthetic_only-informational)

**A working offline SOC detection-engineering project** that reads security event logs, identifies potentially malicious behaviors, maps alerts to MITRE ATT&CK, creates situational awareness reports, and tracks incident cases through their lifecycle.

Built as a portfolio lab for **SOC Analyst / Cybersecurity Engineer** applications. Uses synthetic data and runs locally—**no cloud account, network scanning, credentials, or Azure subscription required**.

> **Portfolio scope:** The Python tool is implemented and testable. The example Microsoft Sentinel queries are provided for study and adaptation but **have not been deployed or validated in a Microsoft Sentinel tenant**. Heuristics are not proof of compromise.

## Demo: findings from 18 synthetic events

```text
Analyzed 18 events; created 6 findings.
  SOC-bb6ce9ca7b21  HIGH    T1110       Successful logon following repeated failures
  SOC-b33cc4444cd8  HIGH    T1110.003   Possible password spraying
  SOC-b8d02e45012b  HIGH    T1059.001   PowerShell with encoded command argument
  SOC-f668b23e3314  HIGH    T1098.007   Privileged group membership modification
  SOC-55fe4d81aac0  HIGH    T1070.001   Windows security event log cleared
  SOC-650c4ee8a783  MEDIUM  T1110.001   Repeated failed authentication
```

See the generated [Markdown sample report](reports/sample-report.md) and [machine-readable JSON report](reports/sample-report.json).

## Why this project matters for a SOC Analyst role

| SOC requirement | Evidence in this repository |
| --- | --- |
| Monitor logs and security events | `ingest.py`: normalize JSONL log exports and validate timestamps |
| Investigate SIEM alerts | `detection.py`: transparent detection logic and event correlation |
| Perform incident triage | `casebook.py`: SQLite case status, analyst and timestamped notes |
| Map adversary behaviors | Six detection patterns mapped to MITRE ATT&CK IDs |
| Communicate findings | `reporting.py`: customer-style situational awareness report |
| Write response playbooks | `docs/INCIDENT_PLAYBOOKS.md`: triage, containment approvals, recovery |
| Work with Microsoft Sentinel | `sentinel/kql/`: sample KQL for Windows security events |
| Improve and test detections | `tests/`, tunable `config/detections.json`, GitHub Actions CI |

## Quick start (Windows, macOS, Linux)

**Prerequisite:** Python 3.10 or newer.

```bash
# From the extracted repository root
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .

# Scan only local, synthetic data
soc-triage scan --input sample_data/events.jsonl \
  --config config/detections.json \
  --json reports/findings.json \
  --markdown reports/situation-report.md \
  --db reports/cases.sqlite

# View local incident cases
soc-triage cases --db reports/cases.sqlite
```

For PowerShell, enter the scan command on one line or use PowerShell backticks instead of Bash `\` continuations. You can also run the tool without installation using `python -m soc_triage` from the repository root.

**Update a case** using an ID printed during the scan:

```bash
soc-triage update --db reports/cases.sqlite \
  --id SOC-bb6ce9ca7b21 \
  --status investigating \
  --analyst soc-lab-user \
  --note "Confirmed synthetic test event; investigating correlated logons"
```

The case status is persisted between scans. Available statuses: `new`, `triaging`, `investigating`, `contained`, `resolved`, `false_positive`.

## Detection engineering: how it works

1. **Ingest** JSONL events and normalize a subset of Windows SecurityEvent field names, with strict timestamps.
2. **Correlate** authentication events within configurable windows by source IP and account.
3. **Evaluate** behavior rules for PowerShell invocation, privileged groups, and audit log clearing.
4. **Annotate** findings with ATT&CK techniques, severity, evidence, and analyst actions.
5. **Report** findings in JSON and Markdown.
6. **Track** cases in SQLite; update status manually after verification.

| Rule | Heuristic | ATT&CK |
| --- | --- | --- |
| AUTH-001 | ≥5 failed logons to one account from the same IP within 10 min | T1110.001 |
| AUTH-002 | ≥5 distinct accounts with failed logons from the same IP within 15 min | T1110.003 |
| AUTH-003 | Successful logon within 10 min after ≥5 failed logons | T1110 |
| PROC-001 | PowerShell execution with an encoded command parameter | T1059.001 |
| ID-001 | Additions to a privileged local/domain group | T1098.007 |
| LOG-001 | Windows security audit log cleared | T1070.001 |

Rules are **behavioral hypotheses**. Approvals and log correlation are required before any intervention. See [detection coverage](docs/DETECTION_COVERAGE.md), [architecture](docs/ARCHITECTURE.md), and [response playbooks](docs/INCIDENT_PLAYBOOKS.md).

## Input log formats

### Native, normalized schema (synthetic example)

Each line of `sample_data/events.jsonl` is a separate JSON event:

```json
{"timestamp":"2026-10-15T20:00:00Z","event_id":4625,"host":"dc-01.lab.example","source":"windows_security","user":"jordan","src_ip":"203.0.113.24","record_id":"evt-001"}
```

### Microsoft `SecurityEvent`-style export (partial adapter)

`sample_data/sentinel-securityevent-export.jsonl` demonstrates a minimal exported-field mapping:

```json
{"TimeGenerated":"2026-10-15T21:00:00Z","EventID":4625,"Computer":"dc-02.lab.example","TargetUserName":"demo-user","IpAddress":"203.0.113.99","EventRecordId":"sentinel-1"}
```

```bash
soc-triage scan --input sample_data/sentinel-securityevent-export.jsonl
```

**Note:** This is an intentionally limited *offline adapter*, not a complete Sentinel integration. Production schemas and event fields differ by connector and configuration.

## Microsoft Sentinel example hunting queries

See [`sentinel/kql/`](sentinel/kql/) for three illustrative queries targeting Windows failed logons, encoded PowerShell command lines, and security audit log clearance. Queries require workspace-specific validation and appropriate data connectors.

Official docs: [Microsoft Sentinel analytics rule development](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom) · [SecurityEvent table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent) · [MITRE ATT&CK](https://attack.mitre.org/techniques/)

## Automated testing

```bash
python -m unittest discover -s tests -v
```

Tests exercise timestamp parsing, normalization, false-positive boundaries, event correlation, MITRE mappings, SQLite case management, and command-line integration. A GitHub Actions workflow executes the tests and a demo scan on supported Python versions for every push and pull request.

## Repository layout

```text
soc-triage-python/
├── soc_triage/          # Python CLI, event ingestion, detections, case tracking, reports
├── config/              # Tunable rule thresholds and correlation windows
├── sample_data/         # Safe, synthetic Windows and Sentinel-shaped log exports
├── sentinel/kql/        # Illustrative Microsoft Sentinel hunting queries
├── docs/                # Architecture, incident playbooks, detection coverage
├── reports/             # Sample SOC situational-awareness outputs
├── tests/               # Automated unit and integration test suite
├── .github/workflows/   # CI tests and reproducible demo
├── pyproject.toml       # Installable Python CLI application
├── LICENSE
└── README.md
```

## Limitations and safe-use guidelines

- No live SIEM, Azure workspace, production monitoring, or enterprise integration is claimed.
- No active network scanning, malware execution, endpoint blocking, or account disabling. This project is **read-only security-event analysis**.
- Correlation, ATT&CK mappings, and severity ratings are preliminary; a qualified analyst must validate alerts.
- Batch detection is not production streaming; outputs are not a substitute for controlled forensics or full enterprise SOC operations.
- Never upload sensitive/production logs, classified data, tokens, authentication secrets, private client information, or unapproved evidence to public GitHub. Command-line logs can contain sensitive data.
- Review any alerts before requesting containment and follow organizational incident response procedures.

## Suggested next enhancements

1. Add unit-tested Sigma-style detection rule definitions and automated coverage checks.
2. Add a containerized Wazuh or Sentinel *test* integration with recorded, non-sensitive event samples.
3. Add suppression policies, allowlists, analyst feedback loops, and detection rule quality metrics.
4. Add incident timeline clustering, richer Windows Event ID mapping, and forensic evidence export metadata.
5. Write a short case study explaining the six findings, false positives, triage conclusions, and playbook updates.

---


