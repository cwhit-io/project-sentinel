# Operations

This is a future protected operator runbook for the commissioning baseline. The project is non-operational, not production-ready, and unsuitable for real credentials. For the boundary between Sentinel and operator-managed concerns, see [`docs/scope.md`](scope.md); PostgreSQL backup, OpenBao, and TLS termination are operator-managed outside this repository.

## Add an asset

For a future protected run, create `inventory/assets/<id>.yaml` with required metadata, approved templates, owner, maintenance window, and template references. Inventory stores no credentials; operators store them on the host filesystem at known paths and Sentinel reads from there. Local validation and dry-run evidence generation are implemented, but live enrollment, connectivity, and apply are not accepted. No applicable plan creation path exists. Identity-bound signed approval is a blocker, and ordinary CLI `--approve` is not approval.

For HTTP uptime assets, set `collection_method: http`, declare one or more `http_checks` with the closed `name`, `target_url`, `method: GET`, `interval_seconds`, `timeout_seconds`, `expected_status_codes`, `follow_redirects`, and `verify_tls` fields, and provide at least one host group. HTTP uptime assets must not declare an `interface` block, must not include any templates, and must be tagged with `scope: <target>` so the scope-isolated reconcile run can find them. Scope isolation enforces that a `sentinel reconcile --scope <target>` run sees only assets whose `tags.scope` matches.

## Policies and dashboards

Add conservative policy intent to `monitoring/policies/` with duration, recovery, dependency, severity, route, runbook, and remediation status. Add dashboards only for supported panels backed by real data. Regenerate the catalog; do not edit it manually.

## Plan, drift, and maintenance

`sentinel plan` always emits `mode: dry-run`, including when `--dry-run` is omitted. Verified artifacts accept only that review-only mode. `sentinel apply` is hard-disabled before artifact parsing, receipt writing, or any future mutation adapter, even with `--approve` or a recomputed integrity checksum. `sentinel rollback` verifies dry-run evidence and reports that review is required; it performs no reverse operation.

## Reconcile, sign, apply, receipt

See [`docs/reconcile.md`](reconcile.md) for the operator runbook. In summary:

* `sentinel reconcile --dry-run --scope <target>` writes the plan and a sanitized bundle to `~/sentinel-state/runs/<id>/`.
* `sentinel reconcile --apply-if-signed --scope <target>` validates the existing detached SSH signature or auto-signs when the operator has enabled auto-sign.
* `sentinel reconcile` is the **only** path that can ever apply a plan; the apply gate is the verified SSH signature plus the explicit `--apply-if-signed` flag.
* Apply opens the exact `WriteZabbixClient`, dispatches one call per plan operation in order, re-verifies via the read client, and writes a sanitized receipt.

## Investigate failed collection

Check the asset address, maintenance state, agent/SNMP availability, time synchronization, firewall path, and Zabbix poller health. Operator-managed credential rotation happens outside Sentinel; never place credentials in inventory or command arguments.

## Alert testing

In a future isolated commissioning test, use a safe lab target and force a reversible condition. Verify firing, route delivery, duration, dependency suppression, recovery threshold, and notification-only receipt. This was not tested end-to-end. Compose currently has no StackStorm deployment or automation profile; do not execute remediation or test destructive workflows.

## Protected-live reconciliation gate

Future commissioning must use HTTPS. The sole HTTP exception is an explicit opt-in for a literal `127.0.0.1` or `::1`, with an explicit port and exact `/api_jsonrpc.php` path. Artifact storage must be a pre-existing canonical absolute owner-mode-`0700` directory outside the worktree. The target binding is derived from the actual exact client; a caller cannot supply endpoint, trust, handle, or binding identity. Bundle reads revalidate closed desired/snapshot/plan semantics and reject oversized, non-finite, partial, cross-run, and digest-linked tampering. Approval verification rejects invalid signatures before mutation; the live executor remains hard-disabled before parsing, credential access, network access, or filesystem access.

Artifact checks reduce but cannot eliminate filesystem races. Use only a protected local filesystem for a future reviewed read ceremony.