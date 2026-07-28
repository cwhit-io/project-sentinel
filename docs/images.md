# Image verification inventory

This is an image inventory for the commissioning baseline, not deployment evidence. Compose now uses readable `tag@repository-digest` references matching the tested local image digests supplied for this correction. A repository digest makes the configured reference immutable; it does **not** establish publisher identity, signature verification, provenance, continuing registry availability, runtime health, or production acceptance.

An operator attested that a bounded registry check resolved each of the five exact
configured `name:tag@sha256` references shown below at that point in time. This is
not durable acceptance or independently retained pull evidence. It does not
authenticate the publisher or establish signature, attestation, provenance,
vulnerability, runtime-health, or production evidence.

| Component | Immutable Compose reference / tested local digest | Runtime evidence | Authenticity/signature | Production acceptance |
|---|---|---|---|---|
| PostgreSQL | `postgres:16.4@sha256:e62fbf9d3e2b49816a32c400ed2dba83e3b361e6833e624024309c35d334b412` | Disposable core and bounded restore observations exist; see commissioning records. | **Blocked / not verified** | **Blocked** |
| Zabbix server | `zabbix/zabbix-server-pgsql:ubuntu-7.0.14@sha256:f5115f824d5c0e619bd5af63e42c89e87a46d0b83231d05cdb7211edee66a77b` | Disposable core/transport observations exist; no end-to-end monitoring acceptance. | **Blocked / not verified** | **Blocked** |
| Zabbix web | `zabbix/zabbix-web-nginx-pgsql:ubuntu-7.0.14@sha256:83f6e5bead0344d14f185373650d3ece3f902c95717eaa87e5a9b1b9d28512e2` | Disposable web/API observations exist; no authenticated apply or production boundary acceptance. | **Blocked / not verified** | **Blocked** |
| Zabbix agent2 | `zabbix/zabbix-agent2:ubuntu-7.0.14@sha256:0cdb9c87064d3fb604cfcc10721a90c7e69ffb2aec8310ba3282ee1dc9c700de` | Synthetic transport observation only; no registration or target acceptance. | **Blocked / not verified** | **Blocked** |
| OpenBao | `openbao/openbao:2.2.0@sha256:19612d67a4a95d05a7b77c6ebc6c2ac5dac67a8712d8df2e4c31ad28bee7edaa` | Sealed/uninitialized compatibility observation only; bootstrap and secret use were not performed. | **Blocked / not verified** | **Blocked** |

The operator-attested point-in-time registry resolution is not durably accepted.
The tested local digests and immutable pins remain recorded configuration facts,
not authenticity claims or a guarantee of continuing registry availability. No
registry signature, publisher identity, attestation, or provenance was verified.
Before an upgrade, review release and compatibility notes, independently establish
the approved digest and authenticity policy, update the readable tag and digest
together, and repeat bounded health, monitoring, backup/restore, and rollback checks.

No runnable StackStorm image is inventoried. The former unsupported monolithic `stackstorm/stackstorm:3.8.0` service was removed rather than replaced with an incomplete component set. StackStorm notification routing remains disabled desired-state intent until a complete, reviewed deployment design and separate runtime evidence exist.
