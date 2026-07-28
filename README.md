# Sentinel

Sentinel is a self-hosted, Git-driven infrastructure monitoring commissioning baseline. The intended design uses Zabbix for monitoring, PostgreSQL for Zabbix state, StackStorm for approved automation events, OpenBao for credentials, and a small operator for deterministic Zabbix plans. This repository is non-operational and is not production-ready.

## Current Status

The recorded work includes local/static evidence and one torn-down disposable core runtime. PostgreSQL, Zabbix server, and Zabbix web were started with a synthetic database secret; no production services, real credentials, recovery material, or targets were used. Compose has no runnable StackStorm service; its contracts remain disabled intent. The current test count is recorded in `STATUS.md`; earlier lower-count runs are historical. Do not use this checkout with real credentials or real monitoring targets.

The implementation can validate the sample inventory and build a review-required dry-run plan. Apply is unconditionally disabled: it rejects before parsing or mutation and writes no receipt. Export reports that no live export was performed.

The sample inventory contains no real credentials and does not claim that any asset is monitored. Credential enrollment, live connectivity, review/apply, and production bootstrap are not commissioning evidence and require a separate protected, approved procedure.

## Layout

- `inventory/`: schema-validated assets and sites
- `monitoring/`: policies, approved templates, dashboards, routes, and generated exports
- `automation/`: controlled Zabbix and StackStorm integration
- `scripts/`: operator, backup, and validation entry points
- `docs/`: architecture, operations, recovery, security, and generated monitoring catalog

See `STATUS.md`, `docs/architecture.md`, and `docs/operations.md`. This repository intentionally does not ship production credentials or a public ingress, and makes no full runtime acceptance or production-readiness claim.
OpenBao bootstrap and recovery are documented in `docs/openbao.md`; image verification status is in `docs/images.md`.
