# Zabbix restored-application evidence

**Scope:** disposable technical observations from application startup against a streamed PostgreSQL restore. This is not an accepted milestone, encrypted recovery, or production acceptance.

**Outcome: FAILED / NOT ACCEPTED.** The independent validator run used unrestricted `docker inspect` and exposed synthetic environment fields in private output. Values are intentionally not repeated. This is an evidence-handling incident; the technical observations below require safe field-scoped revalidation in a future separately approved run.

## Evidence identity

- Restore/application start window: `2026-07-28T05:41:23Z` to `2026-07-28T05:41:33Z`
- Internal network: `sentinel-restore-app-net`
- PostgreSQL container: `a05198cf7577560c71fe20c69682b620bccec8346faab9e2b0de9f468cc06cbe`
- Zabbix server container: `eeed68d6ba43053a1d1976a617e6b1265b746cca851b164cc0e8b565254578a9`
- Zabbix web container: `a60ded103ba24abd2137458eebd027538219fc2ed0a0f3a03fcb6b090b80d98c`

## Operator-recorded technical observations

- A fresh PostgreSQL 16.4 destination was created on a dedicated `internal=true` Docker network.
- A fresh `pg_dump -Fc` stream from the disposable source was restored with `--clean --if-exists --no-owner --no-privileges`.
- Source and destination selected aggregates matched: `203|392|17659|6718|7000000` (public tables, hosts, items, triggers, mandatory schema version).
- Zabbix server 7.0.14 started against the restored database and its server process remained ready.
- Zabbix web 7.0.14 started against the restored database and returned internal HTTP `200`.
- All three containers had restart count `0` at evidence capture.
- The network had exactly three members and no container published a host port.

Synthetic database values existed only in the disposable container environments. No password value, database row content, dump stream, or monitoring credential is included in this record.

## Acceptance boundary

These observations do **not** establish or independently validate bounded Zabbix server/web startup compatibility. Validator handling failed, so the restored-application milestone is not accepted. They also do not establish retained/encrypted artifact recovery, repeatability, independent event provenance, complete database equivalence, global roles, PITR, host registration, monitoring, dashboards, alerting, image authenticity, or production recovery readiness.

## Cleanup

All disposable source, restore, and application containers, project networks, named volumes, and explicitly inventoried anonymous volumes were removed. Unrelated volumes/images and commissioning TLS were preserved. No real credentials or recovery material were used.
