# Security

These are intended controls for the commissioning baseline. They are not a security assessment or runtime acceptance, and this repository is unsuitable for real credentials. For what Sentinel owns versus what is operator-managed, see [`docs/scope.md`](scope.md).

Secrets and PostgreSQL backup are operator-managed outside Sentinel. Zabbix and StackStorm are trusted upstream platforms; Sentinel does not add 2FA, MFA, rate limiting, fail2ban, or other runtime hardening to either platform. Sentinel stores no credentials in inventory, logs, dashboards, exports, fixtures, process arguments, or chat. OpenBao bootstrap, recovery, audit, and secret storage are operator-managed outside Sentinel and are not part of this repository.

Compose declares no public bind addresses. PostgreSQL and the synthetic agent remain off all operator bridges; no StackStorm service or operator bridge exists. There is no shared operator Docker bridge, but host-routed, Docker-gateway, LAN, and Internet paths remain unverified; no categorical no-lateral or bounded-egress claim is made. Per `docs/scope.md`, TLS termination and any reverse proxy are operator-managed and not configured by Sentinel.

Zabbix discovery and apply identities must be separate and least privilege; no routine super-admin token. The inert StackStorm contracts express allowlist, validation, audit, cooldown, concurrency, and disabled-by-default intent only; no runtime enforcement exists in this checkout. Human approval is required for credential enrollment, plan apply, drift adoption/replacement, any complete StackStorm deployment, and remediation enablement.
