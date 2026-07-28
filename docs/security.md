# Security

No public ports are defined. Use a TLS reverse proxy or trusted network with authentication, and restrict host firewall access. Secrets belong in OpenBao, not Git, logs, dashboards, exports, fixtures, process arguments, or chat. Enable OpenBao audit logging and verify values are absent. Alert on unavailable or unauthorized secret access, expiration, failed refresh, revoked bootstrap use, and backup failure.

Zabbix discovery and apply identities must be separate and least privilege; no routine super-admin token. StackStorm workflows are allowlisted, validated, bounded, audited, cooldown-protected, concurrency-protected, and disabled by default. Human approval is required for credential enrollment, bootstrap, plan apply, drift adoption/replacement, and remediation enablement.
