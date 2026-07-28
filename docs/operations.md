# Operations

This is a future protected operator runbook for the commissioning baseline. The project is non-operational, not production-ready, and unsuitable for real credentials. Only a disposable PostgreSQL/Zabbix core was exercised; no target, credential, or end-to-end workflow was accepted.

## Add an asset

For a future protected run, create `inventory/assets/<id>.yaml` with required metadata, approved templates, owner, maintenance window, and `secret://` references. Local validation and dry-run evidence generation are implemented, but live enrollment, connectivity, and apply are not accepted. No applicable plan creation path exists. Identity-bound signed approval is a blocker, and ordinary CLI `--approve` is not approval.

## Policies and dashboards

Add conservative policy intent to `monitoring/policies/` with duration, recovery, dependency, severity, route, runbook, and remediation status. Add dashboards only for supported panels backed by real data. Regenerate the catalog; do not edit it manually.

## Plan, drift, and maintenance

`sentinel plan` always emits `mode: dry-run`, including when `--dry-run` is omitted. Verified artifacts accept only that review-only mode. `sentinel apply` is hard-disabled before artifact parsing, receipt writing, or any future mutation adapter, even with `--approve` or a recomputed integrity checksum. `sentinel rollback` verifies dry-run evidence and reports that review is required; it performs no reverse operation. A separately designed identity-bound signature and approval protocol, review, and tests are required before any applicable artifact format or apply path may exist.

## Investigate failed collection

Check the asset address, maintenance state, agent/SNMP availability, time synchronization, firewall path, certificate/PSK reference, and Zabbix poller health. Rotate or revoke credentials through OpenBao, never by placing them in inventory or command arguments.

## Alert testing

In a future isolated commissioning test, use a safe lab target and force a reversible condition. Verify firing, route delivery, duration, dependency suppression, recovery threshold, and notification-only receipt. This was not tested end-to-end. Compose currently has no StackStorm deployment or automation profile, so receipt is blocked until a complete design is reviewed; do not execute remediation or test destructive workflows.

## Credential enrollment

`sentinel credentials add NAME` is an implementation path that requires a protected `OPENBAO_TOKEN` and a reachable OpenBao instance; it was not executed. In an approved protected environment it must prompt with no echo, write directly to OpenBao, and return only an opaque reference and redacted status. Separate collection, bootstrap, remediation, API, StackStorm, database, and backup identities.
