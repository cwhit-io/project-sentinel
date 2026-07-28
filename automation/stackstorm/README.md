# StackStorm Boundary

Only named workflows in the allowlist may receive Zabbix events. Remediation is notification-only by default. StackStorm must retrieve credentials from OpenBao at execution time; event payloads contain asset IDs and opaque references only. Workflow handlers need target allowlists, validation, timeouts, retry limits, cooldowns, concurrency locks, post-action checks, audit records, and a manual disable switch before approval.
