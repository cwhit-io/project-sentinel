# Sentinel

Sentinel is a self-hosted, Git-driven infrastructure monitoring commissioning baseline. Sentinel owns desired-state inventory and monitoring policy, deterministic validation, catalog, and plan generation, plus mocked or read-only reconciliation boundaries. Zabbix and StackStorm are trusted upstream platforms. See [`docs/scope.md`](docs/scope.md) for what Sentinel does and does not do. This repository is non-operational and is not production-ready.

## Current Status

A user-approved synthetic local commissioning beta is running for bounded local login testing; Sentinel is not production operational. The user/operator attests that frontend login succeeded and that “everything looks good”; no frontend credential was received or recorded here. The Zabbix `Admin` password was changed by the user. PostgreSQL, Zabbix server, Zabbix web, and the disposable lab agent independently passed bounded health and transport checks. No production services, real credentials, recovery material, monitoring apply, StackStorm, OpenBao, or encrypted backup were used. Compose has no runnable StackStorm service; its contracts and all notification routes remain disabled intent. The current evidence is recorded in `STATUS.md`. Do not use this checkout with real credentials or real monitoring targets.

## Layout
- `inventory/`: schema-validated assets and sites
- `monitoring/`: policies, approved templates, dashboards, routes, and generated exports
- `automation/`: controlled reconciliation boundaries
- `scripts/`: validation and operator entry points
- `docs/`: architecture, scope, operations, security, evidence, and the generated monitoring catalog

See `STATUS.md`, `docs/architecture.md`, `docs/operations.md`, and the canonical boundary in [`docs/scope.md`](docs/scope.md). Image verification status is in `docs/images.md`.
