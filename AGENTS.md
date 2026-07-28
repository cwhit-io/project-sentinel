# Sentinel Operator Guide

**Repository status: commissioning baseline, non-operational, and unsuitable for real credentials.** The documented local evidence does not constitute runtime acceptance or production readiness.

Sentinel uses Zabbix for collection, discovery, dashboards, problems and alert evaluation; PostgreSQL for Zabbix state; StackStorm for named, approved remediation workflows; OpenBao for secrets; and Git as the desired-state, audit and recovery layer.

## Rules

- Desired state lives in `inventory/` and `monitoring/`; `docs/monitoring-catalog.md` and `monitoring/exports/` are generated.
- Secrets are referenced as `secret://...` only. Never print, commit, log, export, or embed secret values.
- Codex uses `sentinel plan` and reviewed `sentinel apply`; direct database modification and unrestricted Zabbix API calls are prohibited.
- Remediation can only call allowlisted StackStorm workflows and is notification-only until explicitly approved.
- Preserve existing user changes. Deployment is not accepted until runtime health and representative monitoring verification succeed; those checks are not evidenced by this checkout.

## OpenCode orchestration

The project-local OpenCode configuration defines `sentinel-coordinator` as the primary agent and the only normal user-facing entry point. Use:

```text
@sentinel-coordinator continue Sentinel commissioning
```

The coordinator owns decomposition, non-overlapping file assignments, integration, status, review, validation, and the final report. It may invoke only `sentinel-implementer`, `sentinel-reviewer`, and `sentinel-validator`; subagents cannot invoke other agents because task permission is denied and `subagent_depth` is one. Do not relay prompts between agents.

The standard lifecycle is:

```text
inspect -> plan -> implement -> reviewer audit -> remediation -> validator verification -> coordinator integration -> user report
```

The coordinator must request reviewer audit after every security-sensitive milestone and validator verification after every implementation milestone. Reviewer findings go back to the implementer for bounded correction, followed by repeat review and validation after critical fixes. `STATUS.md` must record the current phase, completed evidence, blockers, and next safe action.

No agent may request or handle plaintext credentials. No agent may start production services, initialize OpenBao, create recovery material, enroll real credentials, connect real infrastructure, apply monitoring changes, or run remediation without explicit user approval. Missing tools, skipped tests, unavailable runtime, and unverified claims are blocked or not tested, never passes. Git initialization or commits require secret scanning first and explicit user approval.

## Validation and operations

The commissioning record distinguishes static checks from runtime checks. A future protected run may use `python -m pytest`, `python scripts/sentinel.py validate`, `python scripts/sentinel.py catalog`, `docker compose config`, and `python scripts/sentinel.py plan --dry-run`; these commands do not prove runtime acceptance. Reconcile only after review, approval, protected credentials, and live verification are available.

`scripts/backup.sh` creates only an encrypted PostgreSQL logical dump, encrypted validated dry-run plan metadata, and an encrypted manifest. It does **not** create a sanitized live Zabbix configuration export. That requires a separately implemented and verified export path and is currently blocked. Roll back only a recorded, reviewed plan using `sentinel rollback`; restore backups according to `docs/recovery.md`. Human approval is required for applying plans, adopting UI drift, enabling remediation, enrolling credentials, and production bootstrap access.

The Compose definition is intended to use a trusted network or TLS reverse proxy boundary and loopback-bound ports, but this was not runtime-tested. Do not declare deployment complete until health checks, a safe firing/recovery test, StackStorm receipt without action, idempotent reconciliation, exports, and backups have been demonstrated with evidence.
