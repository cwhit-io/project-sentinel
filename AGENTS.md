# Sentinel Operator Guide

Sentinel uses Zabbix for collection, discovery, dashboards, problems and alert evaluation; PostgreSQL for Zabbix state; StackStorm for named, approved remediation workflows; OpenBao for secrets; and Git as the desired-state, audit and recovery layer.

## Rules

- Desired state lives in `inventory/` and `monitoring/`; `docs/monitoring-catalog.md` and `monitoring/exports/` are generated.
- Secrets are referenced as `secret://...` only. Never print, commit, log, export, or embed secret values.
- Codex uses `sentinel plan` and reviewed `sentinel apply`; direct database modification and unrestricted Zabbix API calls are prohibited.
- Remediation can only call allowlisted StackStorm workflows and is notification-only until explicitly approved.
- Preserve existing user changes. Deployment is incomplete until runtime health and representative monitoring verification succeed.

## Validation and operations

Run `python -m pytest`, then `python scripts/sentinel.py validate`, `python scripts/sentinel.py catalog`, and `docker compose config`. Use `python scripts/sentinel.py plan --dry-run` for a dry run. Reconcile with `sentinel plan`, review the output, then `sentinel apply --plan <file> --approve` and verify before exporting with `sentinel export`.

Back up PostgreSQL and export sanitized Zabbix configuration with `scripts/backup.sh`. Roll back only a recorded, reviewed plan using `sentinel rollback`; restore backups according to `docs/recovery.md`. Human approval is required for applying plans, adopting UI drift, enabling remediation, enrolling credentials, and production bootstrap access.

The compose stack assumes a trusted network or TLS reverse proxy boundary. It does not expose Zabbix, PostgreSQL, StackStorm, or OpenBao publicly. Do not declare deployment complete until health checks, a safe firing/recovery test, StackStorm receipt without action, idempotent reconciliation, exports, and backups have been demonstrated.
