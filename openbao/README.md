# OpenBao Operations

This directory contains desired-state configuration only. TLS files, initialized
state, audit output, tokens, unseal keys, recovery keys, and root credentials
must remain outside Git under the ignored `private/openbao/` and `openbao/`
runtime paths. No Compose service initializes or unseals OpenBao.

## Production requirements

- Provide a CA and a server certificate whose SAN includes `openbao`, plus the
  matching private key, at `private/openbao/tls/{ca.crt,server.crt,server.key}`.
- Start the explicit `secrets` profile only after reviewing the mounted TLS and
  storage paths. The service has persistent data and a separate audit volume.
- Initialize and unseal using an approved operator workstation and a documented
  quorum ceremony. Store recovery material in an approved offline mechanism;
  never write it to this repository, `.env`, Compose output, or logs.
- Enable a file audit device to `/openbao/audit/audit.log` during the same
  controlled bootstrap. Audit enablement is intentionally not automated here.
- Bind application identities to the narrow policies in `policies/`; do not use
  root tokens for applications and revoke bootstrap credentials after setup.

The Compose healthcheck verifies TLS without disabling certificate validation.
`bao status` exit `0` means reachable and unsealed; exit `2` means reachable but
sealed or uninitialized. Both satisfy this narrow health probe, while every other
exit fails it. Health proves only API/TLS reachability and is not initialization,
unseal, runtime acceptance, or production-readiness evidence.
