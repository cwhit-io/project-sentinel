# OpenBao sealed-start evidence

**Scope:** disposable synthetic commissioning only. This is not bootstrap, recovery, or production acceptance.

## Evidence identity

- Recorded UTC start: `2026-07-28T04:59:36Z`
- Compose project/namespace: `sentinel-evidence-openbao`
- Compose config hash: `6f0c764cea04ef1dd1c117b5fc9a71776503ba6447a9f4ffc315ce6326df70cc`
- Tracked-file `git diff --binary` SHA-256 after evidence correction: `bd52243231be4a2632d1e343c41053dee2c7bfbe3983249ddaac1f4403e197d1`
- Image ID: `sha256:19612d67a4a95d05a7b77c6ebc6c2ac5dac67a8712d8df2e4c31ad28bee7edaa`
- Local repository digest: `openbao/openbao@sha256:19612d67a4a95d05a7b77c6ebc6c2ac5dac67a8712d8df2e4c31ad28bee7edaa`
- Platform: `linux/amd64`

The local digest identifies the tested bytes but is not signature or publisher-provenance verification.

## Sanitized results

- Corrected physical-root/fixed-path preflight: passed before startup.
- Container: running, Docker health `healthy`, restart count `0`.
- OpenBao CLI status: `initialized=false`, `sealed=true`; the CLI omitted `standby` in this state.
- CA-verified default loopback health request: HTTP `501`, expected for an uninitialized instance.
- CA-verified loopback reachability request with explicit `sealedcode=200&uninitcode=200`: HTTP `200` through `127.0.0.1:18200`; the health response reported `standby=true`.
- Effective publication: exactly `127.0.0.1:18200 -> 8200/tcp`.
- Configured user: `0:0` (commissioning-only compatibility mode).
- Read-only root filesystem: enabled.
- Added capabilities: `DAC_READ_SEARCH`, `IPC_LOCK` only.
- Dropped capabilities: `ALL`; `DAC_OVERRIDE` was not added.
- Security option: `no-new-privileges:true`.
- Read-only bind destinations: `/openbao/config`, `/openbao/policies`, `/openbao/tls`.
- Named writable destinations: `/openbao/data`, `/openbao/audit`.
- Bounded tmpfs destinations: `/openbao/file`, `/openbao/logs`, each `rw,nosuid,nodev,noexec,mode=0700`.
- Internal network: `sentinel-evidence-openbao-secrets`, one member.
- Dedicated non-internal operator network: `sentinel-evidence-openbao-openbao-operator`, one member.
- No shared operator Docker bridge was used.

## Prohibited operations

No initialization, unseal, authentication, bootstrap-helper phase, credential enrollment, secret write, recovery-material generation, monitoring apply, or remediation was performed. TLS and key contents were not included in this evidence.

## Acceptance boundary

This evidence establishes sealed/uninitialized OpenBao compatibility, CA-verified loopback reachability, and the inspected container boundary for the identified image/config/worktree state. It does not establish image authenticity, production hardening, firewall/egress controls, audit/KV/policy behavior, backup/restore, recovery custody, or production readiness. Numeric root and process-wide `DAC_READ_SEARCH` remain production blockers.
