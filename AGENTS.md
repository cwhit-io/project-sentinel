# Sentinel Operator Guide

**Repository status: commissioning baseline, non-operational, and unsuitable for real credentials.** See [`docs/scope.md`](docs/scope.md) for the canonical boundary decisions dated 2026-07-28.

Sentinel owns desired-state inventory and monitoring policy, deterministic validation/catalog/plan generation, and mocked or read-only reconciliation boundaries. Zabbix and StackStorm are trusted upstream platforms. Secrets and PostgreSQL backup are operator-managed outside Sentinel.

## Rules
- Desired state lives in `inventory/` and `monitoring/`; generated catalog and exports are derived artifacts.
- Never request, print, commit, log, export, or embed secret values. Inventory contains no credentials; operators manage host-side references.
- Use `sentinel plan` and reviewed `sentinel apply`; apply remains disabled and direct database modification/unrestricted Zabbix API calls are prohibited.
- Remediation is notification-only intent and may call only approved upstream workflows.
- Preserve user changes. Static checks do not establish runtime acceptance.

## Orchestration
The coordinator owns decomposition, review, validation, integration, status, and final reporting. No agent may connect real infrastructure, apply monitoring changes, enroll credentials, or execute remediation.

## Validation
Scoped static checks include pytest, `python scripts/sentinel.py validate`, `catalog`, and `plan --dry-run`. These do not prove runtime acceptance. See `docs/scope.md` before proposing future work.
