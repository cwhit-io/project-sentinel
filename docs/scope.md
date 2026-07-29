# Sentinel Scope

**Canonical boundary statement, dated 2026-07-28.** This file is the single source of truth for what Sentinel owns and what is operator-managed outside Sentinel. Future AI agents must not rediscover, re-implement, or take responsibility for any item listed as out of scope.

## Boundary decisions

1. **TLS is terminated by an existing Cloudflare tunnel** that forwards to the local Zabbix web at `10.10.97.18:18080`. Sentinel does not implement TLS, certificates, reverse proxies, or any TLS-related Compose configuration.
2. **Zabbix and StackStorm are trusted complete upstream platforms.** Sentinel does not harden them, add 2FA, rate limiting, fail2ban, MFA, or modify their configurations.
3. **PostgreSQL backup is handled by an existing database install outside this repository.** Sentinel does not implement, run, or test backup scripts, encrypted artifacts, age keys, restores, or recovery runbooks for PostgreSQL.

## What Sentinel does own
- Desired-state inventory under `inventory/` and monitoring policy under `monitoring/`.
- Deterministic `sentinel validate`, `sentinel catalog`, and `sentinel plan --dry-run` generation.
- Mocked or read-only reconciliation boundaries (planned v3) under `automation/reconciliation/`.
- Generated catalog at `docs/monitoring-catalog.md` and plan at `monitoring/exports/plan.json`.
- Local static checks: pytest, `sentinel.py` commands, `docker compose config`, yamllint, secret-pattern scan.

## What Sentinel does not own
- Any TLS termination, certificate, reverse proxy, or `127.0.0.1:443→127.0.0.1:18080` style binding as Sentinel's responsibility.
- Zabbix or StackStorm hardening, 2FA, rate limiting, fail2ban, MFA, or configuration mutation.
- OpenBao bootstrap, recovery material, audit, unseal, AppRole issuance, secret storage, or preflight.
- `scripts/backup.sh`, encrypted PostgreSQL dumps, age identity, manifests, offsite custody, restore repeatability, or production recovery.
- Real credentials, secret values, recovery keys, tokens, PSKs, or sensitive environment values in inventory, plans, logs, or evidence.

## Future AI prohibitions
Future AI agents and contributors must **not**:
- Add or reference TLS configuration, reverse proxies, certificates, or `127.0.0.1:443→127.0.0.1:18080` style mappings as Sentinel features.
- Add OpenBao bootstrap, recovery, audit, or preflight code or documentation back into this repository.
- Add `scripts/backup.sh`, encrypted backup artifacts, age key handling, restore scripts, or `docs/recovery.md` style runbooks for PostgreSQL.
- Add 2FA, rate limiting, fail2ban, MFA, or other hardening to Zabbix, StackStorm, or OpenBao as Sentinel features.
- Modify the binding of `10.10.97.18:18080`.
- Introduce credentials or secret values into inventory, plans, logs, exports, fixtures, or command arguments.

## References
- `AGENTS.md` and `README.md` reference this scope statement as the canonical boundary.
- `docs/architecture.md`, `docs/security.md`, `docs/operations.md` reference this scope statement for the boundary between Sentinel and operator-managed concerns.
