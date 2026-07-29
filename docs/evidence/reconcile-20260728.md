# Reconcile mocked self-test — static evidence

Date: 2026-07-28

## Scope and result

This is static, mocked-only, and disposable evidence. It exercises the
closed `sentinel reconcile` workflow against in-memory clients, locally
generated Ed25519 SSH keypairs, and a tmp-dir state directory. No live
Zabbix endpoint, no real credential, no live OpenBao secret, and no
production identity were ever contacted or used.

The new evidence complements `reconciliation-v3-static-20260728.md` and
`reconciliation-live-gate-static-20260728.md`. The previous read-only
gate evidence remains authoritative for the read path. This evidence
documents the bounded mocked apply path, the HTTP inventory schema, and
the approval and credential-provider interfaces. It does not establish
runtime trust, real identity, or production readiness.

## Commands and observed results

- `python3 scripts/sentinel.py validate` — exit 0; two assets validated
  (`sentinel-lab-agent` and `bhm-org-uptime`) without inspecting secret
  values.
- `python3 scripts/sentinel.py catalog` — exit 0; deterministic catalog
  regenerated at `docs/monitoring-catalog.md`.
- `python3 scripts/sentinel.py plan --dry-run` — exit 0; sanitized plan
  regenerated at `monitoring/exports/plan.json` with both assets and
  `templates: []` for the HTTP uptime asset.
- `python3 scripts/sentinel.py reconcile --dry-run --scope public-uptime
  --state-dir <tmp> --approval-key <tmp-key>` — exit 5 (awaiting
  approval); the run directory contained `plan.json`, `desired.json`,
  `observed.json`, `signing-template.json`, and the plain-English
  summary "I will create host `bhm-org-uptime`; add http test
  `homepage` against https://blackhawkministries.org/; add item
  `Response time for homepage` (key `web.test.in[homepage]`). Plan
  requires approval."
- `PYTHONPATH=/tmp/opencode/sentinel-python-tools:/tmp/opencode/sentinel-extra-tools
  python3 -m pytest -q tests/test_reconcile.py` — **21 passed** in
  ~1.1 seconds. The suite exercises validate → normalize → discover →
  plan → sign → apply → verify → receipt, the auto-sign and manual-sign
  paths, wrong/expired/missing signatures, missing scope tags,
  cross-scope transitions, missing private keys, scope mismatches, and
  the `FileCredentialProvider` mode/owner/symlink/empty guards.
- `PYTHONPATH=/tmp/opencode/sentinel-python-tools:/tmp/opencode/sentinel-extra-tools
  python3 -m pytest -q tests/test_http_inventory_schema.py` — **16
  passed** in ~1.2 seconds. The suite covers missing `url`,
  `interval_seconds < 60`, `interval_seconds > 3600`, `timeout_seconds <
  1`, `timeout_seconds > 30`, duplicate `http_check` names, invalid
  status codes (`99`, `600`, `999`, `"two-hundred"`), the explicit
  rejection of code `999`, the acceptance of code `404`, missing
  `follow_redirects`, HTTP hosts with `interface`, and agent hosts with
  `http_checks`.
- Original 2026-07-28 baseline:
  `PYTHONPATH=/tmp/opencode/sentinel-python-tools:/tmp/opencode/sentinel-extra-tools
  python3 -m pytest -q` — **150 passed** in ~12 seconds.
- `PYTHONPATH=/tmp/opencode/sentinel-extra-tools python3 -m yamllint
  automation/zabbix/api-policy.yaml automation/zabbix/api-policy.schema.yaml
  automation/zabbix/probe-policy.yaml automation/zabbix/probe-policy.schema.yaml
  automation/zabbix/delete-policy.yaml automation/zabbix/delete-policy.schema.yaml`
  — exit 0.
- Assigned-file-only `detect-secrets scan` — exit 0; no findings
  reflected in any output beyond the exit code.
- `git diff --check` — exit 0.

### Typed discovery dispatch follow-up (2026-07-29)

The live CLI wire-up exposed a static integration defect before any live API
was invoked: `discover()` called generic `.request()` even though the exact
`ReadZabbixClient` deliberately exposes only named read methods. The fix
routes the six discovery operations through `api_version()`, `get_templates()`,
`get_hostgroups()`, `get_hosts()`, `get_httptests()`, and `get_items()` when
the exact protected read client is supplied. Non-read-client test doubles
continue to use `.request(method, params)`, preserving the inert mocked
transport path. The protected-live gate now supplies its exact read client
directly instead of wrapping only a subset of those methods.

Observed static commands for this follow-up:

- `python3 -m pytest -q tests/test_zabbix_reconciliation_v3.py
  tests/test_zabbix_live_gate.py tests/test_reconcile.py` without the repository
  test-tool `PYTHONPATH` — exit 1 with `/usr/bin/python3: No module named pytest`;
  no tests ran.
- `PYTHONPATH=/tmp/opencode/sentinel-python-tools:/tmp/opencode/sentinel-extra-tools
  python3 -m pytest -q tests/test_zabbix_reconciliation_v3.py
  tests/test_zabbix_live_gate.py tests/test_reconcile.py` — **141 passed** in
  11.38 seconds.
- `PYTHONPATH=/tmp/opencode/sentinel-python-tools:/tmp/opencode/sentinel-extra-tools
  python3 -m pytest -q` — **161 passed** in 12.50 seconds.

The new negatives/dispatch evidence asserts that the client returned by
`build_read_client()` has no generic `.request()` surface and that its typed
`api_version()` delegates to the bounded transport call. A separate synthetic
HTTP-host discovery test confirms typed `httptest.get` and `item.get` dispatch
and normalized attachment to the observed host. Existing reconciliation v3
tests continue to exercise the generic `.request()` compatibility path.
No external endpoint or operator credential was used; static success does not
establish authenticated runtime compatibility. In particular,
`automation/zabbix/transport.py` was outside this follow-up's assigned files
and its current transport-level `READ_METHODS` allowlist omits `httptest.get`
and `item.get`. The discovery dispatcher now reaches the named client methods,
but a real transport call for those two methods remains blocked pending a
separately assigned transport-policy correction and review.

## Behavior covered

The reconcile suite covers the closed contract for:

* synthetic in-process generation of an Ed25519 SSH keypair;
* manual `ssh-keygen -Y sign` producing a `0600` detached signature;
* `auto_sign_or_stop` returning `False` when the operator has not enabled
  auto-sign, and writing a fresh `0600` signature when the marker exists;
* `verify_detached` rejecting malformed payloads, unreadable signature
  files, non-canonical keys, wrong namespaces, and bad signatures;
* the closed sanitized receipt contract (`receipt_version: 2`,
  `status: converged`, RFC3339 UTC timestamps, closed
  `operation_results` fields, `verified_after` mapping);
* the in-memory write-client dispatch path including
  `create_host`, `create_httptest`, `create_item`, and the
  rejected `update_*` / `delete_*` operations;
* the `FileCredentialProvider` mode (`0600` or stricter), ownership
  (running user), symlink, and empty-content checks; and
* the targets module refusing any plan that contains a disabled
  operation.

The HTTP inventory schema suite covers the closed contract for
`collection_method: http`, `http_checks` field shape and bounds, and the
explicit if/then/not clauses that forbid `interface` on HTTP hosts and
`http_checks` on agent hosts.

## Limitations

These results exercise closed in-process fakes, synthetic keys, and tmp
state directories. They do not establish runtime trust, identity
provenance, transport compatibility, real Zabbix authentication,
deletion eligibility, file-descriptor durability, or production
readiness. The auto-sign marker and the `FileCredentialProvider` are
included as scoped templates; Sentinel never wires them by default.

## Live reconcile against sentinel.bhm.li

The `sentinel reconcile --source live-discovery` code path was wired in
this milestone (see `STATUS.md` and `docs/reconcile.md`), and the 2026-07-29
follow-up corrected its generic-versus-typed discovery dispatch before any
live attempt. No live run was performed in either session. Per the repository
commissioning baseline (`docs/scope.md`, `AGENTS.md`) and the explicit task
constraint "Do not run live API", Sentinel did not connect to
`sentinel.bhm.li`, did not read an operator credential file, and did not
execute the documented command. Synthetic disposable credential-file fixtures
were used only by local tests. The operator's command for a future live run is:

```
python3 scripts/sentinel.py reconcile \
    --source live-discovery \
    --scope public-uptime \
    --credential-handle zabbix-read \
    --state-dir ~/sentinel-state \
    --approval-key ~/.config/sentinel/trusted-approvers/approval.ed25519
```

Without `--apply-if-signed`, the command is expected to write a plan to
`~/sentinel-state/run-<unix-ms>-public-uptime/plan.json` (plus
`desired.json`, `observed.json`, and `signing-template.json`) and exit
`0`. With `--apply-if-signed`, the unwired write factory causes the
command to exit `70` after the signature check. No exit code, run
directory, plan file list, or operation count from a live run is
recorded here; recording them requires the operator to execute the
command and capture the evidence.