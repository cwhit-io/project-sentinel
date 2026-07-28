# Sentinel

Sentinel is a self-hosted, Git-driven infrastructure monitoring baseline. Zabbix monitors approved assets, PostgreSQL stores Zabbix state, StackStorm receives approved automation events, OpenBao stores credentials, and a small operator turns reviewed YAML into deterministic Zabbix plans.

## Start

1. Copy `.env.example` to `.env` and set local values using a protected secret mechanism. Do not put credentials in Git.
2. Start only verified services: `docker compose up -d` (OpenBao is a separate protected commissioning step; never start it in dev mode).
3. Validate: `python scripts/sentinel.py validate && python scripts/sentinel.py catalog`.
4. Check services: `docker compose ps` and open the Zabbix UI on the trusted host boundary.
5. Generate a no-op plan: `python scripts/sentinel.py plan --dry-run`.

The sample inventory contains no real credentials and does not claim that a production asset is monitored. Add a real asset with a `secret://` reference, enroll it with `sentinel credentials add <name>`, review the plan, and apply only after connectivity and ownership have been confirmed.

## Layout

- `inventory/`: schema-validated assets and sites
- `monitoring/`: policies, approved templates, dashboards, routes, and generated exports
- `automation/`: controlled Zabbix and StackStorm integration
- `scripts/`: operator, backup, and validation entry points
- `docs/`: architecture, operations, recovery, security, and generated monitoring catalog

See `docs/architecture.md` and `docs/operations.md`. This repository intentionally does not ship production credentials, a public ingress, or a claim of runtime verification in an environment where Docker and target infrastructure were unavailable during setup.
OpenBao bootstrap and recovery are documented in `docs/openbao.md`; image verification status is in `docs/images.md`.
