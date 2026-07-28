# OpenBao commissioning

Compose deliberately runs OpenBao only with `server -config`, persistent file storage, TLS 1.3+, and no token or secret in application configuration. The TLS directory is ignored by Git and must be provisioned locally with protected permissions. Do not use dev mode.

## Protected bootstrap procedure

An operator with an approved recovery-material delivery plan must run these commands locally, in a protected terminal, and store recovery shares and the initial administrative token in separate approved locations. Never paste their output into tickets, logs, chat, or Git:

```sh
docker compose --profile secrets up -d openbao
docker compose exec openbao bao operator init -format=json
docker compose exec openbao bao operator unseal
docker compose exec openbao bao operator unseal
docker compose exec openbao bao operator unseal
docker compose exec openbao bao audit enable file file_path=/openbao/audit/audit.log
docker compose exec openbao bao policy write sentinel-read /openbao/policies/sentinel-read.hcl
```

The `init` output is recovery material. This project does not run it automatically because secure delivery cannot be guaranteed locally. Use an approved threshold and custody process, then revoke the bootstrap token after creating short-lived, least-privilege identities. Set token TTL/max TTL and periodic renewal on those identities; revoke immediately on rotation or incident. The application must use only those identities through the protected local secret loader.

The policy file must be mounted or loaded through a protected operator workflow before use. Root-token use is bootstrap-only and must never be placed in `.env`, Compose, application config, or command history.

## TLS and audit checks

Provision a certificate for the local trusted name and key with restrictive permissions under `private/openbao/tls/`. Verify the certificate chain and expiry before startup. Confirm the audit device is enabled and that audit files are access-controlled. Do not use `-tls-skip-verify` except for the local healthcheck; operator commands must set `BAO_ADDR` and `BAO_CACERT`.

## Backup and recovery

Back up the OpenBao data volume and audit records using the protected, encrypted procedure in `docs/recovery.md`. Recovery shares must be held separately from encrypted backups. Restore into an isolated disposable instance and verify policy, audit, token expiry, and revocation before any production recovery.
