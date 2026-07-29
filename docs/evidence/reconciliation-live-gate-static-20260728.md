# Reconciliation protected-live gate — static evidence

Date: 2026-07-28

## Scope and result

This is static and disposable evidence only. The implementation defines a
protected-live read boundary while keeping every plan non-applicable and every
execution path blocked. It does not establish authenticated Zabbix compatibility,
runtime trust, artifact durability/TOCTOU resistance under failure, approval acceptance,
or production readiness.

No live API, real credential, beta mutation, apply, StackStorm, backup, or
OpenBao operation was performed. The HTTP test server was a synthetic local,
disposable fixture. No key pair was generated or signature was accepted.

## Commands and observed results

- `python3 -m compileall -q automation/zabbix/transport.py automation/reconciliation/artifacts.py tests/test_zabbix_live_gate.py` — exit 0.
- `python3 scripts/sentinel.py validate` — exit 0; one synthetic asset validated
  without inspecting credential values.
- `PYTHONPATH=/tmp/opencode/sentinel-python-tools python3 -m pytest -q tests/test_zabbix_live_gate.py`
  — **65 passed** in 5.24 seconds (including 7 parametrized
  `test_bundle_publication_failures_release_run_and_permit_retry` cases).
- `PYTHONPATH=/tmp/opencode/sentinel-python-tools python3 -m pytest -q tests/test_zabbix_live_gate.py tests/test_zabbix_reconciliation_v3.py`
  — **107 passed** in 7.36 seconds.
- Final `PYTHONPATH=/tmp/opencode/sentinel-python-tools python3 -m pytest -q` —
  **194 passed** in 20.70 seconds.
- `PYTHONPATH=/tmp/opencode/sentinel-extra-tools python3 -m yamllint automation/zabbix/api-policy.yaml automation/zabbix/api-policy.schema.yaml automation/zabbix/delete-policy.yaml automation/zabbix/delete-policy.schema.yaml`
  — exit 0.
- Assigned-file-only `detect-secrets scan` using the external extra-tools path
  — exit 0 with **0 findings**; output was reduced to exit status and count, so
  no finding value was emitted. The first attempt through the Python-tools path
  was unavailable and exited 1; ignored and unassigned files were not scanned.
- Synthetic, generated-in-process `POSTGRES_PASSWORD` plus fixed disposable
  namespace/database identifiers with `docker compose ... --profile secrets
  config --quiet` — exit 0 with no output; no service was started and the value
  was not stored.
- Assigned-file `git diff --check` — exit 0.
- Host `python3 -m pytest ...` — blocked: host Python has no pytest module.
- Host `yamllint ...` was unavailable; the external dependency path above passed.

The focused tests exercised a disposable literal-IPv4-loopback HTTP stub;
sanitized acquisition, consume, malformed-return, factory, request, response,
and parse failures without reflecting synthetic sensitive exception text;
non-2xx status, wrong content type, non-identity encoding, oversized and
truncated bodies, malformed and duplicate-member JSON, wrong JSON-RPC
version/ID, result-plus-error, malformed and valid API errors, and network
failure; credential-buffer erasure after every failure where a mutable buffer
was obtained; endpoint
rejection; and denial
of `host.update`, `host.create`, `hostinterface.update`, and `host.delete` before
parameter, credential-provider, mock-transport, or network access. They also
covered exact-type anti-duck checks, internally
derived target binding, `/tmp`-backed mode/overwrite/worktree controls, closed
bundle tamper/cross-run/partial/non-finite/oversize rejection, and denial before
exploding approval/executor inputs. Artifact negatives cover foreign tags in
each of desired, observed, and plan, malformed/unknown Sentinel tags, sensitive-
looking foreign label/value non-reflection, exact locator/secret-like fields and
references, absence of the complete run path after rejection, reservation
release for desired/observed/plan and final-preflight failures, closed-order
failure, and successful reservation of the same run ID after each rejection.

## Limitations and follow-up

The read-only live workflow was not connected to the running beta and no
credential provider implementation exists. A first future protected ceremony
requires exactly one opaque least-privilege read-token reference, never its value.
A later write token and approval key require a separate design and authorization;
no approval verification is currently accepted. Independent review, validator
rerun, exact runtime trust/compatibility checks, and descriptor-pinned artifact
and filesystem-failure testing remain required. Current path/mode/fsync checks do
not eliminate TOCTOU or prove crash/power-loss durability. Apply, mutation,
retries, receipt persistence, and the retired UI runbook remain unavailable.
`host.delete` is present only as an inert unavailable tombstone policy with
`executor: none`; no delete executor is available.
