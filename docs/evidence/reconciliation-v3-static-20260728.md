# Reconciliation v3 static validation evidence

Date: 2026-07-28

## Scope

This is sanitized, static-only evidence for the mocked reconciliation v3
correction. The focused and full validator invocations were run separately. No
service, network target, live API, credential store, monitoring apply, receipt
persistence, deletion, backup, or remediation was contacted or executed.
“Independent” below means separate command invocations; it does not claim a
second operator, runtime verification, or production acceptance.

## Independent command evidence

- `PYTHONPATH=/tmp/opencode/sentinel-python-tools python3 -m pytest -q tests/test_zabbix_reconciliation_v3.py`
  completed successfully: **42 passed**.
- `PYTHONPATH=/tmp/opencode/sentinel-python-tools python3 -m pytest -q`
  completed successfully: **129 passed**.
- `python3 scripts/sentinel.py validate` completed successfully and reported one
  validated synthetic asset without inspecting secret values.
- `python3 -m compileall -q automation/reconciliation tests/test_zabbix_reconciliation_v3.py`
  completed successfully with exit status zero.
- `git diff --check` completed successfully with exit status zero.
- A scoped, no-output Python regular-expression scan of this evidence file for
  private-key markers, opaque secret-reference URIs, and credential-assignment
  forms completed with zero matches. No matched content or raw command output
  was retained. `rg` was unavailable, so it was not used as scan evidence.

The host Python installation did not provide pytest. The passing pytest results
used the pre-existing external dependency path shown above; no dependency was
installed into this repository.

## Behavior covered

The focused suite covers closed receipt and operation-result fields, strict
identifier/digest/timestamp grammars and enums, valid identifier substrings,
mixed create/update/quarantine binding, missing/duplicate/reordered results,
independent interface identity reassignment and reuse, and shared identity
rejection across two creates. The serialized receipt substring denylist was
removed; acceptance now follows the closed field sets and per-field validation.

## Limitations

These results exercise exact inert fakes and pure in-memory transitions only.
They do not establish live Zabbix compatibility, authenticated identity,
runtime receipt provenance or durability, applicable plans, deletion
eligibility, deployment readiness, or production acceptance.
