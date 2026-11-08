# Analyst incident response playbooks (training)

These are manual review playbooks aligned to a typical incident lifecycle. Every containment or corrective action requires authorization and applicable agency procedures.

## Playbook 1: Repeated failed authentication / possible password spraying

1. **Validate:** Confirm event IDs, login type, tenant/host, timestamps, affected accounts, source IP, and data ingestion quality.
2. **Triage:** Determine whether the source is an approved proxy, vulnerability test, identity sync, or user error. Assess source reputation using approved enterprise sources.
3. **Scope:** Search for related successful logons (4624), lockouts (4740), MFA challenges, and identity alerts. Determine first/last seen and affected account count.
4. **Escalate:** Notify the designated incident owner if compromise is suspected. Record ATT&CK T1110.001 or T1110.003 as hypotheses, not confirmed attribution.
5. **Contain with approval:** Review applicable identity controls, token revocation, password reset, or IP controls in accordance with incident policy.
6. **Recover and learn:** Confirm authorized users regain access; update detections, exclusions, and runbooks.

## Playbook 2: Suspicious PowerShell execution

1. **Validate:** Determine exact host, user, process and parent, command line, signer, and whether approved administration is expected.
2. **Scope:** Correlate with event 4688, Sysmon 1, PowerShell script-block logs, endpoint detections, and subsequent file/network activity.
3. **Investigate:** Analyze script content in a safe, isolated forensic environment under organization procedures. Never run untrusted commands from telemetry.
4. **Escalate and contain:** Coordinate endpoint isolation or session controls only with the assigned incident commander.
5. **Preserve:** Retain timestamps, hashes, EDR case references, and evidence handling records.
6. **Learn:** Tune T1059.001 detection and add missing endpoint log sources.

## Playbook 3: Privileged group modification / log clearing

1. **Validate:** Confirm the exact audit event, actor, host, affected group, and any approved change request.
2. **Scope:** Identify the added member through the full original event; investigate follow-on administrative logons and other directory changes.
3. **Check audit continuity:** For 1102, verify whether a separate security product or SIEM retained logs across the gap.
4. **Escalate:** Notify IAM/SOC leads and preserve event evidence; apply the organization-specific incident severity rubric.
5. **Contain with approval:** Revert unauthorized privilege changes only after coordinating with operations.
6. **Document:** Update the casebook with triage notes, indicators, disposition, and prevention recommendations.

## Documentation template

- Case ID / alert ID:
- Analyst and UTC timestamps:
- Affected assets/accounts:
- Evidence and source systems:
- ATT&CK hypothesis and confidence:
- False-positive checks:
- Triage outcome / severity rationale:
- Containment authorization and implementation:
- Recovery checks / lessons learned:
