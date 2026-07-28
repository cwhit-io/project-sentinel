# PostgreSQL disposable restore evidence

**Scope:** an operator/validator-attested demonstration of one exact timestamped disposable PostgreSQL restore and a live, bounded selected-aggregate comparison only. This is not durable acceptance, complete database equivalence, a repeatability milestone, an encrypted-backup test, offsite-custody evidence, application-startup evidence, or production recovery acceptance.

## Method

- Source: container `2a3be4a24a953cd4f3e0db5f8d79698e2726af4107a275061e2551522038e269` in Compose project `sentinel-evidence-zabbix`.
- Destination: isolated disposable container `sentinel-restore-postgres` using `postgres:16.4` and `--network none`.
- Transfer: the operator recorded `pg_dump -Fc` streaming directly to `pg_restore` over a process pipe and recorded that no dump file was written or retained. No durable dump artifact or stream hash exists, so the direct-pipe/no-dump account and stream contents cannot be independently reconstructed after execution.
- The exact second restore used `--clean --if-exists --no-owner --no-privileges`.
- The operator described the second execution as a clean-option rerun into the same mutable destination used by the first execution. It was not an independent restore into a fresh destination.

## Execution identity

- First restore, operator-recorded only: `2026-07-28T05:18:35Z` to `2026-07-28T05:18:41Z`. Its outcome is not independently or durably verified.
- Exact second restore, operator/validator-attested demonstration: `2026-07-28T05:21:14Z` to `2026-07-28T05:21:21Z`; the operator and validator observed exit `0` and the exact clean options.
- Destination container ID: `7754684def477047514a669216724cc57bfbab91dc391e78fa27bbe4cfbda238`
- Destination anonymous volume: `2231cf6ce8f39f9220586fb20774e3a2bdb48dacbb9cc8f1c800f8d7242d275d`
- Destination image: `postgres:16.4`
- Destination network mode: `none`

The operator and validator attested that they observed the exact second timestamped restore, its `--clean --if-exists --no-owner --no-privileges` options, and exit `0`. They also observed matching current source and destination selected aggregates after that restore. Those runtime events have expired, no durable dump or event capture was retained, and this evidence file remains uncommitted with the commissioning worktree. The demonstration is therefore not durably accepted and Git-history provenance is not established. The earlier first execution remains operator-recorded only, and generalized repeatability remains blocked.

## Sanitized results

- Destination PostgreSQL readiness was observed during validation but is not durably evidenced.
- First restore: operator-recorded outcome only; not independently or durably verified and not a passed milestone.
- Exact second restore: operator/validator-attested bounded demonstration for the recorded timestamp, exact clean options, and exit `0`; not durably accepted.
- Current selected aggregate equivalence after the second restore: live/bounded observation. The source and same mutable destination matched across:
  - public schema table count;
  - host row count;
  - item row count;
  - trigger row count;
  - mandatory database schema version.
- Aggregate order was public tables, hosts, items, triggers, mandatory schema version; the live source and destination comparison returned `203|392|17659|6718|7000000` for both. This selected aggregate does not establish complete database equivalence, row-level equality, or a historical signature proof.
- Destination had no network connectivity and no published port.

No password value was included in this evidence or in recorded dump output; no dump stream, API credential, or row content was retained. Synthetic database credentials existed in the disposable container environment while it was running. No dump artifact or artifact hash exists for later verification.

## Acceptance boundary

This records only an operator/validator-attested demonstration of the exact second timestamped disposable PostgreSQL restore and a live/bounded selected-aggregate match for the tested PostgreSQL/Zabbix database. It is not durably accepted because the evidence is uncommitted and the transient runtime events have expired. Because the demonstrated rerun reused one mutable destination, it was not an independent fresh restore and generalized repeatability remains blocked. The aggregate is not complete database equivalence. Encrypted artifact creation, age identity/custody, manifest integrity or offsite publication, roles/global objects, point-in-time recovery (PITR), application startup from the restored database, version-upgrade compatibility, Zabbix configuration export recovery, OpenBao recovery, and production recovery remain blocked or not tested. It is not production acceptance.
