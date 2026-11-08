# Microsoft Sentinel KQL examples

These **illustrative hunting queries** bridge the local Python lab to Sentinel concepts from the target SOC Analyst position. They are NOT imported, deployed, or tested in a real Microsoft Sentinel workspace; no Azure subscription is required to run the Python project.

- `failed_logins.kql`: Windows Event ID 4625 with per-account and per-IP aggregation.
- `powershell_encoded.kql`: Windows Event ID 4688 process commands resembling PowerShell encoded invocation. Requires process command-line auditing; Windows telemetry can include sensitive content.
- `windows_log_cleared.kql`: Event ID 1102 signals Windows Security log clearing.

## Production readiness checklist

1. Confirm the `SecurityEvent` table is populated and inspect the actual field names and values.
2. Validate query lookback and result samples against benign operations and authorized tests.
3. Verify alert entity mapping, severity, schedule, and MITRE ATT&CK tagging in the Sentinel rule interface.
4. Route alerts through a documented incident review process. Never auto-contain hosts based on these heuristics alone.
5. Tune exclusions and thresholds after measuring false positives and ingestion gaps.

Official documentation:
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent
- https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom
