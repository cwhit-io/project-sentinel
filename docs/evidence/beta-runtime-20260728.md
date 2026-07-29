# Local commissioning beta runtime evidence

Evidence time: `2026-07-28T14:02:33Z`

Scope: user-approved local, synthetic-only login testing. This evidence does not
authorize real credentials, real targets, monitoring apply, OpenBao bootstrap,
backup execution, StackStorm, remediation, or production use.

## Independently verified

- Compose project: `sentinel-beta-20260728`.
- Exactly four services: PostgreSQL, Zabbix server, Zabbix web, and the disposable
  synthetic Zabbix agent.
- All four containers were running and healthy with restart count `0`.
- Effective images matched the four digest-pinned Compose references.
- Web publication was exactly `127.0.0.1:18080 -> 8080/tcp`.
- Server publication was exactly `127.0.0.1:11051 -> 10051/tcp`.
- PostgreSQL and the synthetic agent had no host publication.
- No OpenBao project container was present.
- Application, database, and monitoring networks were internal. The non-internal
  Zabbix operator network contained only Zabbix server and web.
- Web returned HTTP `200`; the unauthenticated API reported version `7.0.14`.
- Zabbix server queried the synthetic agent successfully: `agent.ping=1`.
- Tested non-loopback host-address connections to both published ports were
  refused; addresses were not recorded.
- Reviewer found no critical or high defect within the authorized checks and
  accepted the runtime for bounded local login testing only.
- Independent validator checks at `2026-07-28T14:02:33Z` passed the bounded
  service, image, health, restart, publication, network, web, API, non-loopback
  refusal, and agent-transport assertions. Authentication was not attempted by
  an agent.

## Operator-attested frontend observation

After those independent checks, the user/operator attested that frontend login
succeeded and that “everything looks good.” This is an operator-attested browser
observation only; no credential was requested, received, printed, or recorded by
an agent or in this repository. No authentication negative testing, authorization
boundary testing, lockout/session testing, or other authentication security
testing was performed. The attestation does not establish monitoring or
production acceptance.

The operator also historically field-scoped verified that `zabbix_sender` was
available in the existing Zabbix server container. No sender value was executed.
The former manual UI/sender procedure is retired: `docs/beta-monitoring-test.md`
is historical, superseded, and must never be executed. The only current next
path is automated reconciliation, which remains mocked-only and non-applicable.

## Credential handling

The database value was synthetic, generated inside an isolated launch process,
and was not printed or written to a file. It remains available to privileged
Docker metadata while the containers exist. No frontend credential was requested,
received, printed, or tested by an agent.

## Limitations

Authentication negative/security testing, authorization boundary testing,
registration, monitoring data, dashboards, alerts,
apply, drift handling, backup, recovery, TLS ingress, OpenBao, StackStorm, egress,
firewall behavior, soak testing, and production operation remain unaccepted or
untested. The frontend uses plain HTTP on loopback. The generated database value
was intentionally not retained; restarting existing containers is distinct from
recreating them against the retained volume. This is a disposable commissioning
beta, not production acceptance.
