# Image verification inventory

| Component | Image/version | Digest | Upstream | License | Verification date | Upgrade procedure |
|---|---|---|---|---|---|---|
| PostgreSQL | `postgres:16.4` | blocked: registry digest not verified locally | https://hub.docker.com/_/postgres | PostgreSQL License | 2026-07-28 | Review release notes, verify signature/digest, test backup/restore, update Compose, run health and reconciliation checks |
| Zabbix server | `zabbix/zabbix-server-pgsql:ubuntu-7.0.14` | blocked: registry digest not verified locally | https://hub.docker.com/r/zabbix/zabbix-server-pgsql | AGPL-3.0 | 2026-07-28 | Review Zabbix compatibility, verify digest, test schema backup/restore and representative alerts, then update both Zabbix images |
| Zabbix web | `zabbix/zabbix-web-nginx-pgsql:ubuntu-7.0.14` | blocked: registry digest not verified locally | https://hub.docker.com/r/zabbix/zabbix-web-nginx-pgsql | AGPL-3.0 | 2026-07-28 | Verify digest and matching server version, test TLS boundary and healthchecks, then update Compose |
| OpenBao | `openbao/openbao:2.2.0` | blocked: registry digest not verified locally | https://hub.docker.com/r/openbao/openbao | MPL-2.0 | 2026-07-28 | Review release notes, verify digest, test TLS/init policy/audit and isolated recovery before upgrade |
| StackStorm | `stackstorm/stackstorm:3.8.0` | blocked: registry digest not verified locally | https://hub.docker.com/r/stackstorm/stackstorm | Apache-2.0 | 2026-07-28 | Verify upstream support and digest, test notification-only receipt, review allowlists and rollback before update |

No digest is claimed because the registry and image signatures were not verified in this commissioning run. Deployment acceptance is blocked until every image is independently verified and recorded.
