# Operations

## Add an asset

Create `inventory/assets/<id>.yaml` with required metadata, approved templates, owner, maintenance window, and `secret://` references. Run `python scripts/sentinel.py validate`, generate the catalog, then `sentinel plan --dry-run`. Human review is required before apply.

## Policies and dashboards

Add conservative policy intent to `monitoring/policies/` with duration, recovery, dependency, severity, route, runbook, and remediation status. Add dashboards only for supported panels backed by real data. Regenerate the catalog; do not edit it manually.

## Plan, drift, and maintenance

Use `sentinel plan`, inspect unmanaged/conflicting objects, and choose explicitly to adopt or replace UI changes. Apply only a reviewed plan. Schedule maintenance through the approved Zabbix operation and ensure alerts are suppressed for the documented window.

## Investigate failed collection

Check the asset address, maintenance state, agent/SNMP availability, time synchronization, firewall path, certificate/PSK reference, and Zabbix poller health. Rotate or revoke credentials through OpenBao, never by placing them in inventory or command arguments.

## Alert testing

Use a safe lab target and force a reversible condition. Verify firing, route delivery, duration, dependency suppression, recovery threshold, and StackStorm receipt. The initial StackStorm mode is notification-only; do not test destructive workflows.

## Credential enrollment

`sentinel credentials add NAME` launches the protected enrollment boundary; the implementation must prompt with no echo and write directly to OpenBao. It must return only an opaque reference and redacted status. Separate collection, bootstrap, remediation, API, StackStorm, database, and backup identities.
