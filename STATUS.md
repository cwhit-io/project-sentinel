# Project Status

**Status: a synthetic local Zabbix commissioning beta is running and independently passed bounded health, publication, API, and agent-transport checks. The user/operator attests successful frontend login and “everything looks good”; production acceptance remains blocked per [`docs/scope.md`](docs/scope.md).**

## Public ingress (commissioning beta)

On 2026-07-28 the user confirmed that a Cloudflare tunnel already terminates TLS for the public hostname `sentinel.bhm.li` and forwards plain HTTP to the local Zabbix web at `10.10.97.18:18080`. The Zabbix `Admin` account password was changed by the user before this URL was reachable. The Cloudflare-side TLS terminates outside this repository; the LAN path from the tunnel connector to the web container is plain HTTP and is not separately authenticated. This is a **commissioning beta ingress only**; it is not a production ingress and any Zabbix configuration touched through this URL is disposable. See `docs/beta-public-ingress.md` for the operator notes.

## Current phase

On 2026-07-28 the user clarified that upstream Zabbix and StackStorm are trusted and bounded this milestone to Sentinel's integration only. A mocked-first Zabbix reconciliation v3 implementation has passed bounded static validation: closed semantic desired/snapshot/ownership/scope/operation contracts, exact inert discovery policy enforcement, deterministic create/update/quarantine pure-state simulation, in-memory receipt validation, hard-disabled receipt persistence, and hard-disabled delete eligibility. The beta runtime and its existing evidence remain untouched.

The approved local commissioning beta runs as Compose project `sentinel-beta-20260728` with loopback-only publication. PostgreSQL, Zabbix server, Zabbix web, and the disposable lab agent passed bounded health and transport checks. The user/operator attests successful frontend login. Authentication negative/security, registration, dashboards, alerts, apply, StackStorm, OpenBao, and encrypted backup remain untested or blocked per `docs/scope.md`. See `docs/evidence/beta-runtime-20260728.md` and `docs/commissioning-report.md`.

The bounded disposable Zabbix core/transport milestone independently passed reviewer audit. PostgreSQL, Zabbix server, Zabbix web, and the synthetic agent were healthy with restart count 0; web/API and server publication were loopback-only, API version was `7.0.14`, server-to-agent `agent.ping` was `1`, and a host-originated agent request was rejected. No agent registration, dashboard/data validation, alerts, authenticated API operation, or monitoring apply occurred.

`docs/beta-monitoring-test.md` is historical, superseded, and must never be executed. The only current next path is automated reconciliation. Its protected-live read scaffold remains non-applicable and was not configured or used against the running beta; mutation remains unavailable.

See `docs/commissioning-report.md` for the evidence and verification matrix. Do not enroll real credentials, apply changes, or declare deployment complete.

## Closed HTTP uptime and mocked-reconcile milestone (2026-07-28)

The reconciliation milestone now also covers a **mocked-only**, **non-applicable** HTTP uptime addition. A second synthetic asset `bhm-org-uptime` is committed to the inventory and validated by `sentinel validate`. The desired-state contract in `automation/reconciliation/v3.py` was extended to accept `collection_method: http` and `http_checks` with the closed fields required by the user. The plan v3 emits `create_host`, `create_httptest`, and `create_item` operations for the HTTP uptime asset. The mocked read client pulls `httptest.get` and `item.get` from the closed read client surface.

The Zabbix API policy was split: `api-policy.yaml` keeps its read-only methods and now also includes `httptest.get` and `item.get` (read-only); a new `probe-policy.yaml` declares the bounded write methods (`host.create`, `host.update`, `httptest.create`, `httptest.update`, `item.create`, `item.update`) and marks `host.delete`, `httptest.delete`, and `item.delete` as `executor: none`. A new exact `WriteZabbixClient`, `WriteJsonRpcTransport`, and `WriteCredentialHandle` enforce role separation: the read and write clients are exact distinct types and cannot cross.

`automation/reconciliation/approval.py` is now a real Ed25519 SSH signature verifier that delegates the cryptography to `ssh-keygen -Y verify`. `automation/reconciliation/approver.py` provides `manual_sign` and `auto_sign_or_stop`. The auto-sign marker file is `~/sentinel-state/auto-sign-enabled`; its presence plus a valid approval key allows future runs to sign automatically. The operator runs `ssh-keygen -Y sign` once for the first manual approval and creates the marker afterwards.

`sentinel reconcile` is the **only** path that can ever apply a plan. `sentinel apply` remains hard-disabled. The reconcile command writes the plan to `~/sentinel-state/runs/<id>/plan.json`, displays a plain-English summary, validates an existing signature or attempts auto-sign, then opens the exact write client only when `--apply-if-signed` is set and a valid signature is present. A sanitized receipt is written to `~/sentinel-state/runs/<id>/receipt.json`. The CLI emits stable exit codes: `0` success, `1` validation, `2` sanitization, `3` read-only preflight, `4` scope isolation, `5` awaiting approval, `64` argument misuse, `70` internal.

`automation/zabbix/credentials.py` now includes a `FileCredentialProvider` template that enforces owner-`uid` and mode-`0600` files. The provider exists only in code; it is never wired by default. No real credential file is read by Sentinel in this milestone.

The full static, mocked evidence is in `docs/evidence/reconcile-20260728.md`.

## Completed evidence

- Repository and scoped `AGENTS.md` guidance inspected.
- Read-only reviewer and validator confirmed available static checks and Compose interpolation.
- Validation, catalog generation, and dry-run plan generation all pass deterministically.
- The sample inventory describes only the disposable runtime identity `sentinel-lab-agent` at `synthetic-zabbix-agent` with built-in template `Linux by Zabbix agent` and no credentials field. The regenerated catalog and dry-run plan are review evidence only.
- The HTTP uptime inventory describes `bhm-org-uptime` against `https://blackhawkministries.org/` with no templates, a single closed `http_check` named `homepage`, scope `public-uptime`, and host group `Sentinel external uptime`. The asset is validated by `sentinel validate` and never applied.
- The mocked reconciliation v3 static evidence records separately invoked focused and full suites at **42** and **129 passed**, validation of one synthetic asset, compilation, diff checking, and a zero-match scoped evidence-file secret-pattern scan. See `docs/evidence/reconciliation-v3-static-20260728.md`.
- The protected-live gate static evidence covers bounded provider/transport/response/parse negatives, exact-type boundaries, internally derived target binding, fail-closed pre-directory artifact persistence with reservation release, and exploding-probe approval/executor denials. See `docs/evidence/reconciliation-live-gate-static-20260728.md`.
- The mocked reconcile evidence covers full validate→normalize→discover→plan→sign→apply→verify→receipt, manual and auto sign paths, wrong/expired/missing signature negatives, missing-scope-tag negatives, missing private key, scope mismatch, closed HTTP inventory schema negatives, and the closed `FileCredentialProvider` owner/mode/symlink guards. The full pytest count is **150 passed**. See `docs/evidence/reconcile-20260728.md`.

## Live reconcile wire-up (2026-07-29)

The `sentinel reconcile --source live-discovery` code path is now wired end to end:

- `automation/zabbix/credentials.py` exposes `build_file_provider(state_dir, handle_id)`, which reads `state_dir/config.yaml`, resolves `credential_handles.<handle_id>.path` with `~` expansion, and delegates to `FileCredentialProvider` for the owner/mode/non-symlink/size/non-empty checks. Every failure raises `CredentialFileError` with one of the closed sanitized messages; no path contents are reflected.
- `automation/reconciliation/cli.py` exposes `build_read_client(handle_id, state_dir)`, which calls `build_file_provider`, builds a `ReadCredentialHandle`, sources the endpoint from `state_dir/config.yaml` under the new top-level `target_endpoint` key (defaulting to `https://sentinel.bhm.li/api_jsonrpc.php`), and assembles a `JsonRpcTransport` with trust id `cloudflare-tls`, `timeout_seconds=10`, `max_request_bytes=65536`, and `max_response_bytes=1048576`. The default endpoint points at the real Zabbix at `sentinel.bhm.li`.
- `scripts/sentinel.py` imports `build_read_client` and passes it as `read_client_factory` to `reconcile_main`. The write path remains unwired (no `build_write_client` exists), so any `--apply-if-signed` invocation exits with `EXIT_INTERNAL` until a separate bounded probe-write integration is approved.
- `tests/test_reconcile.py` adds negative and positive tests covering `build_file_provider` failures (missing config, missing handle, wrong path, wrong mode, symlink, wrong owner) and `build_read_client` wiring (endpoint defaulting and override, handle/path binding, transport contract fields, the read-token-only path assertion, and typed `api_version()` dispatch without a generic `.request()` surface).

A 2026-07-29 static follow-up fixed the live discovery `AttributeError` caused by `discover()` calling the intentionally absent `ReadZabbixClient.request`. Discovery now dispatches `apiinfo.version`, `template.get`, `hostgroup.get`, `host.get`, `httptest.get`, and `item.get` through the exact client's typed methods. Non-`ReadZabbixClient` test doubles retain the legacy `.request(method, params)` path, so the inert mocked transport remains covered. The protected-live gate now passes the exact read client directly rather than recreating a partial generic adapter. Synthetic tests cover both typed HTTP test/item reads and legacy generic mock requests; the latest full suite is **161 passed**.

This session did **not** execute the live reconcile against `sentinel.bhm.li`. No operator credential file was read, no live API call was made, and no plan was produced against the real Zabbix. Tests used only synthetic disposable file content and in-process or loopback fakes. The path is wired and statically validated; the operator must run the documented command from `docs/reconcile.md` to produce a live run. See `docs/evidence/reconcile-20260728.md` for the static evidence and an explicit note that no live run was performed in this milestone.

## Blockers
- Per `docs/scope.md`: TLS termination, OpenBao bootstrap/recovery/audit, Zabbix and StackStorm hardening, and PostgreSQL backup are operator-managed outside Sentinel. Sentinel does not implement, run, or test those concerns.
- Live Zabbix registration/reconciliation, dashboard/data validation, alerting, StackStorm deployment/receipt, image authenticity verification, and production acceptance remain untested or blocked.
- Image publisher/signature/provenance verification remains blocked; see `docs/images.md`.
- The live reconcile code path is wired but unverified at runtime; no live run was performed in this session. Operator execution and review are required before any live evidence is recorded.
- The assigned dispatch fix reaches typed `get_httptests()` and `get_items()` methods, but `automation/zabbix/transport.py` is outside this task's ownership and its current `READ_METHODS` allowlist does not include `httptest.get` or `item.get`. An authenticated transport call for an already-selected HTTP host therefore remains blocked pending a separately assigned transport-policy correction and static review.
- Zabbix v3 has no live transport or authenticated compatibility evidence. Its executor is an in-memory simulator; deletion eligibility and receipt persistence are hard-disabled.

## Next safe action

Pause at this static handoff gate. The next model should rerun Sentinel reviewer and validator against the simplified configuration. Continue only on the automated reconciliation path without contacting the running beta. The manual UI/sender runbook is historical, superseded, and must never be executed. The reconciliation path remains mocked-only and non-applicable pending separate design review, runtime compatibility evidence, and protected identity handling. Do not apply, call a live API, send values, execute deletion, persist receipts, or enable StackStorm/remediation.