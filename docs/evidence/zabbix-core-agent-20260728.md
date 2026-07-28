# Zabbix core and synthetic-agent evidence

**Scope:** disposable synthetic transport and core-service compatibility only. This is not host registration, monitoring, dashboard, alert, or production acceptance.

**Outcome: independently reviewer-passed bounded core/transport milestone.**

## Evidence identity

- Recorded UTC start window: `2026-07-28T05:06:55Z` to `2026-07-28T05:07:22Z`
- Compose project/namespace: `sentinel-evidence-zabbix`
- Tracked-file `git diff --binary` SHA-256 at capture: `bd52243231be4a2632d1e343c41053dee2c7bfbe3983249ddaac1f4403e197d1`
- Platform: `linux/amd64`

| Service | Image ID / local repository digest | Compose config hash |
|---|---|---|
| PostgreSQL | `sha256:e62fbf9d3e2b49816a32c400ed2dba83e3b361e6833e624024309c35d334b412` | `9efe1986178b729b38d911f2358d0642e01a4f69eb8fd70ee0c7238475989012` |
| Zabbix server | `sha256:f5115f824d5c0e619bd5af63e42c89e87a46d0b83231d05cdb7211edee66a77b` | `463bfae0ed5e78c03f043ed71afc6dd5494e4fdfa9e5e4026ba5bddae2bb018a` |
| Zabbix web | `sha256:83f6e5bead0344d14f185373650d3ece3f902c95717eaa87e5a9b1b9d28512e2` | `edbc036abb2dd8514b7c66ff3ad13fa9e8ab2bb2811d430f71944b08af732d48` |
| Zabbix agent 2 | `sha256:0cdb9c87064d3fb604cfcc10721a90c7e69ffb2aec8310ba3282ee1dc9c700de` | `aa28509fa7c84f241d93280146e54de0f9762496d73eb14bfab4276234a202fa` |

The IDs identify tested local bytes but are not signature or publisher-provenance verification.

## Sanitized results

- PostgreSQL, Zabbix server, Zabbix web, and the synthetic agent reached Docker `healthy` with restart count `0`.
- Zabbix web was reachable at loopback-only `127.0.0.1:18082` and returned HTTP `200`.
- Unauthenticated `apiinfo.version` through the loopback API returned `7.0.14`.
- Zabbix server TCP was reachable at loopback-only `127.0.0.1:11051`.
- The Zabbix server successfully queried the synthetic agent over the internal monitoring network: `agent.ping=1`.
- A direct host-originated agent request was rejected because the agent allowlist accepted only `zabbix-server`.
- PostgreSQL had no host publication.
- The synthetic agent had no host publication and belonged only to the internal monitoring network.
- Zabbix server/web used their existing internal networks plus the dedicated non-internal Zabbix operator bridge for loopback publication.

## Deliberately unperformed

The synthetic agent was not registered as a Zabbix host. No authenticated API identity, default credential, monitoring apply, template linkage, item history, dashboard population, trigger, alert, export, or remediation was used. Agent logs reported that active checks could not start because `sentinel-lab-agent` was not registered; this is expected at this acceptance boundary.

## Acceptance boundary

This evidence establishes disposable core health, loopback web/API and server transport, internal server-to-agent passive transport, and host-to-agent rejection. It does not establish actual monitoring, discovery, dashboards, alert firing/recovery, authenticated reconciliation, image authenticity, backup/restore, or production readiness.

After the final restore/application work, all source, restore, and application disposable containers, project networks, named volumes, and explicitly inventoried anonymous volumes were removed. Unrelated volumes/images and commissioning TLS were preserved. No real credentials or recovery material were used.
