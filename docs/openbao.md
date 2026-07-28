# OpenBao commissioning

Compose deliberately runs OpenBao only with `server -config`, persistent file storage, TLS 1.3+, and no token or secret in application configuration. The TLS directory is ignored by Git and must be provisioned locally with protected permissions. Do not use dev mode.

### Disposable Compose compatibility note

The `openbao` service explicitly invokes `bao` and uses numeric `user: "0:0"`.
This retains the static compatibility fix as a **disposable compatibility design**, not a production security or
runtime-acceptance claim. The bounded runtime verification covered sealed compatibility only while OpenBao
remained uninitialized and sealed; bootstrap was not attempted and no recovery
material was generated.

Compose preserves those TLS permissions and adds `DAC_READ_SEARCH` in addition to
`IPC_LOCK`; `DAC_OVERRIDE` remains absent. `DAC_READ_SEARCH` is a broad process-wide
capability that bypasses DAC read/search checks and is accepted only for this
isolated disposable commissioning service, never as a production pattern. Read-only config, policy, and
TLS mounts, a read-only root filesystem, no-new-privileges, the internal secrets
network, and loopback-only host binding remain in place. Compose also attaches OpenBao alone to its
namespace-scoped, non-internal `openbao-operator` bridge. OpenBao does not share
an operator Docker bridge with Zabbix; Compose has no StackStorm service or bridge. That separation does
not establish absence of lateral reachability: host-routed, Docker-gateway, LAN,
and Internet paths remain unverified. Ordinary Docker bridge NAT risk is accepted
by the user only for synthetic sandbox commissioning. Production requires an
explicit firewall and egress design; this is not a production networking pattern.

The Compose healthcheck runs `bao status` with the configured HTTPS address and CA
certificate. Exit `0` (unsealed) and exit `2` (sealed or uninitialized but
reachable) are healthy; every other exit is unhealthy. This check proves only
API/TLS reachability with certificate verification. It does not prove
initialization, unseal, configuration, runtime acceptance, or production readiness.

The image declares writable paths at `/openbao/file` and
`/openbao/logs`, although configured storage and audit paths are `/openbao/data`
and `/openbao/audit`. Compose overrides the unused image paths with mode-`0700`,
`nosuid,nodev,noexec` tmpfs mounts while preserving the two named persistent
mounts. The completed disposable run inspected the expected effective named
data/audit and bounded tmpfs mounts.

## PAUSE GATE — mandatory before initialization or unseal

**STOP. Do not run any `operator init`, `operator unseal`, authentication, or service-start command until the user has explicitly approved a protected, disposable lab run and an operator has confirmed the recovery-material custody plan.** This checkout is a commissioning baseline; no runtime acceptance is implied. The preflight below is only a local file/tool check and does not authorize bootstrap.

### Operator checklist for the synthetic-only disposable lab

- [ ] User approval is recorded for this bounded lab run; no production or real infrastructure is in scope.
- [ ] The operator has acknowledged `SENTINEL_SYNTHETIC_LAB_ACK=I_UNDERSTAND_SYNTHETIC_ONLY_LAB_SCOPE`; this environment marker does not prove human approval.
- [ ] `scripts/openbao-preflight.sh` passes in the intended local workspace.
- [ ] Operator-provided TLS files are already present with restrictive permissions; this project does not generate them.
- [ ] The disposable Compose `lab` profile and synthetic Zabbix target are the only monitoring targets being used.
- [ ] No real hostnames, endpoints, credentials, tokens, or secret values are supplied to the lab.
- [ ] Recovery shares and bootstrap material have separate, approved custodians and a protected delivery path.
- [ ] A teardown and encrypted-backup disposition is agreed before any protected run.
- [ ] `SENTINEL_NAMESPACE` is unique to this disposable lab; preflight collision-checks its named networks and volumes (the default `sentinel` is not assumed free).
- [ ] `COMPOSE_PROJECT_NAME` is set to the same unique value as `SENTINEL_NAMESPACE`; preflight also rejects any existing Docker Compose container carrying the matching `com.docker.compose.project` label. Docker API errors fail closed.
- [ ] Both names use Docker Compose-compatible grammar: a lowercase alphanumeric first character followed only by lowercase alphanumerics, underscores, or hyphens. Empty values, uppercase, dots, leading punctuation, and spaces are rejected.
- [ ] The fixed `private/openbao/tls/` directory itself has exact mode `0700`; config and policy directories are not subject to that exact-mode requirement. Existing TLS file checks still apply.
- [ ] `OPENBAO_TLS_DIR` is unset; preflight rejects even an empty override and always checks the same fixed repository path mounted by Compose and used by the helper.
- [ ] `OPENBAO_PORT` is unset (default `18200`) or a decimal numeric port in `1..65535`; an explicitly empty value is invalid. Preflight requires `ss` and rejects every existing listener on that host port, including wildcard listeners.

### No-init preflight and sealed startup

The old internal-only project `sentinel-overnight-openbao` was independently
verified uninitialized and sealed. Its exact container, network, and named data
and audit volumes were removed; TLS was preserved. Fresh project
`sentinel-night-openbao2` passed preflight and started with the corrected topology.
It was running healthy with restart count 0, and independent status reported
`initialized=false` and `sealed=true`.

Publication was exactly `127.0.0.1:18200->8200`. CA-verified loopback health
returned HTTP 200, while a non-loopback host connection was refused. Networks
were exactly dedicated non-internal `sentinel-night-openbao2-openbao-operator`
and internal `sentinel-night-openbao2-secrets`, each with one member. Effective
inspection confirmed `user 0:0`, capability drop `ALL`, capability add only
`DAC_READ_SEARCH` and `IPC_LOCK`, read-only root, no-new-privileges, read-only
config/policy/TLS binds, expected named data/audit volumes, and bounded tmpfs.
No initialization, unseal, authentication, helper, credentials, or recovery
material occurred. The fresh project was fully torn down and TLS was preserved.
This is sealed compatibility evidence only. Root plus broad capability and
ordinary bridge NAT remain production blockers.

Any future start or bootstrap requires separate approval; this completed evidence
does not authorize either action.

The following is the sanitized guarded command shape used for the completed old-
project teardown. It is retained as evidence and **must not be rerun**. It proved
the exact Compose labels and retained mount design, then removed only the four
independently inventoried resources; it used neither global prune nor a corrected-
Compose `down` command:

```sh
set -eu
OLD_PROJECT='sentinel-overnight-openbao'
OLD_CONTAINER='sentinel-overnight-openbao-openbao-1'
OLD_NETWORK='sentinel-overnight-openbao-secrets'
OLD_DATA_VOLUME='sentinel-overnight-openbao-openbao-data'
OLD_AUDIT_VOLUME='sentinel-overnight-openbao-openbao-audit'

docker info >/dev/null
test "$(docker container inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' "$OLD_CONTAINER")" = "$OLD_PROJECT"
test "$(docker container inspect --format '{{ index .Config.Labels "com.docker.compose.service" }}' "$OLD_CONTAINER")" = 'openbao'
test "$(docker network inspect --format '{{ index .Labels "com.docker.compose.project" }}' "$OLD_NETWORK")" = "$OLD_PROJECT"
test "$(docker volume inspect --format '{{ index .Labels "com.docker.compose.project" }}:{{ index .Labels "com.docker.compose.volume" }}' "$OLD_DATA_VOLUME")" = "$OLD_PROJECT:openbao-data"
test "$(docker volume inspect --format '{{ index .Labels "com.docker.compose.project" }}:{{ index .Labels "com.docker.compose.volume" }}' "$OLD_AUDIT_VOLUME")" = "$OLD_PROJECT:openbao-audit"
test "$(docker container inspect --format '{{range .Mounts}}{{if eq .Destination "/openbao/config"}}{{.Type}}:{{.RW}}{{end}}{{end}}' "$OLD_CONTAINER")" = 'bind:false'
test "$(docker container inspect --format '{{range .Mounts}}{{if eq .Destination "/openbao/policies"}}{{.Type}}:{{.RW}}{{end}}{{end}}' "$OLD_CONTAINER")" = 'bind:false'
test "$(docker container inspect --format '{{range .Mounts}}{{if eq .Destination "/openbao/tls"}}{{.Type}}:{{.RW}}{{end}}{{end}}' "$OLD_CONTAINER")" = 'bind:false'
test "$(docker container inspect --format '{{range .Mounts}}{{if eq .Destination "/openbao/data"}}{{.Type}}:{{.Name}}:{{.RW}}{{end}}{{end}}' "$OLD_CONTAINER")" = "volume:$OLD_DATA_VOLUME:true"
test "$(docker container inspect --format '{{range .Mounts}}{{if eq .Destination "/openbao/audit"}}{{.Type}}:{{.Name}}:{{.RW}}{{end}}{{end}}' "$OLD_CONTAINER")" = "volume:$OLD_AUDIT_VOLUME:true"
test "$(docker container inspect --format '{{if index .HostConfig.Tmpfs "/openbao/file"}}present{{end}}' "$OLD_CONTAINER")" = 'present'
test "$(docker container inspect --format '{{if index .HostConfig.Tmpfs "/openbao/logs"}}present{{end}}' "$OLD_CONTAINER")" = 'present'

docker container stop "$OLD_CONTAINER"
docker container rm "$OLD_CONTAINER"
docker network rm "$OLD_NETWORK"
docker volume rm "$OLD_DATA_VOLUME"
docker volume rm "$OLD_AUDIT_VOLUME"

remaining_container=$(docker ps -aq --filter "name=^${OLD_CONTAINER}$")
remaining_network=$(docker network ls -q --filter "name=^${OLD_NETWORK}$")
remaining_data=$(docker volume ls -q --filter "name=^${OLD_DATA_VOLUME}$")
remaining_audit=$(docker volume ls -q --filter "name=^${OLD_AUDIT_VOLUME}$")
test -z "$remaining_container"
test -z "$remaining_network"
test -z "$remaining_data"
test -z "$remaining_audit"
```

The host TLS, config, and policy bind-source trees are deliberately not removal
targets and must remain untouched. The two tmpfs paths are not independent Docker
resources; their declarations remain in `compose.yaml`, while their old
container-local contents disappear with that one container. Stop on any failed
guard or absence check; do not broaden the removal command.

For any separately authorized future disposable run, run the no-init check in a
clean, fresh namespace immediately before startup; it does not start a container
or contact OpenBao. Its final check validates
`OPENBAO_PORT` (default `18200`) and uses required `ss` output to reject any host
TCP listener on that port. This reduces but cannot eliminate the race before the
separate Compose command.
The completed milestone does not authorize another start. The command shape below
is retained for a future separately approved compatibility check, not acceptance.
The project and namespace must be the same explicit disposable value:

```sh
ROOT=$(pwd -P) # run at the reviewed repository root
export SENTINEL_NAMESPACE='operator-selected-disposable-name'
export COMPOSE_PROJECT_NAME="$SENTINEL_NAMESPACE"
"$ROOT/scripts/openbao-preflight.sh"
docker compose --project-directory "$ROOT" -f "$ROOT/compose.yaml" --project-name "$COMPOSE_PROJECT_NAME" --env-file /dev/null --profile secrets up -d openbao
```

`ROOT` must be set from `pwd -P` while the operator is at the reviewed repository
root. The preflight independently resolves its own physical checkout root from
its script path. These absolute bindings ensure preflight and startup target the
same checkout; do not substitute a generic relative Compose startup command.

Before the Compose command, the protected shell must export `POSTGRES_USER` and
`POSTGRES_PASSWORD` as operator-created, disposable synthetic Compose
interpolation values. They are required even for profile-scoped rendering; no
values are supplied here. Export any optional interpolation overrides there as
needed. `--env-file /dev/null` is mandatory in this Linux commissioning
environment so an ambient repository `.env` cannot be consumed.

The completed unattended sandbox milestone did not clear the bootstrap pause gate.
Do not set the helper confirmation marker or invoke either helper phase during
this run. The marker below is retained only as documentation for a future,
separately approved protected bootstrap ceremony:

```sh
export SENTINEL_OPENBAO_PREFLIGHT_CONFIRMED=I_CONFIRM_OPENBAO_PREFLIGHT_PASSED
```

The `.env.example` `secret://...` entries are reference metadata only and must
not be copied to `.env`. Standard Docker Compose does not dereference them into
secret values; a protected, reviewed shell/secret-loader injection step must
resolve or inject values before any runtime is started, and Compose must use
`--env-file /dev/null`. Do not put resolved values in `.env`, Git, command lines,
or logs.

## Protected bootstrap helper — PAUSED / NOT RUN

The repository contains `scripts/openbao-bootstrap-commissioning.sh`, a local-only
two-phase helper. It is not called by Compose or preflight, and neither phase has
been run in this checkout. All helper actions are prohibited under the current
authorization. Only a future separately approved operator in a protected terminal may
choose **one phase at a time** after the PAUSE GATE is cleared and the sequence
above is complete. The helper requires the explicit
`SENTINEL_OPENBAO_PREFLIGHT_CONFIRMED` marker and does not rerun collision-checking
preflight after resources have been started:

```sh
# Protected operator custody only; values are not supplied by this repository.
SENTINEL_OPENBAO_BOOTSTRAP_ACK=I_UNDERSTAND_PROTECTED_OPENBAO_BOOTSTRAP \
SENTINEL_RECOVERY_CUSTODY_ACK=I_UNDERSTAND_OPERATOR_RECOVERY_CUSTODY \
SENTINEL_SYNTHETIC_LAB_ACK=I_UNDERSTAND_SYNTHETIC_ONLY_LAB_SCOPE \
SENTINEL_NAMESPACE="$COMPOSE_PROJECT_NAME" \
./scripts/openbao-bootstrap-commissioning.sh init
```

The command above is the final step after preflight, sealed startup, and setting
the confirmation marker. `init` validates only the fixed repository path `private/openbao/tls/`; an
`OPENBAO_TLS_DIR` override is rejected so it cannot disagree with the Compose
mount. The helper rechecks that the fixed TLS directory is mode `0700` and uses
`--env-file /dev/null` for every Compose invocation; the required synthetic
Compose interpolation variables must therefore already be exported by the
protected shell. It invokes OpenBao operator init directly on the operator terminal with a
3-share/2-threshold quorum and exits. Recovery shares and initial root material
must be manually secured by the operator under separate approved custody; they
must never be sent to OpenCode, chat, logs, shell history, Git, or this project.
Do not unseal or configure until that custody ceremony is complete.

The `configure` phase requires a protected external bootstrap-token loader marker
(`SENTINEL_OPENBAO_BOOTSTRAP_TOKEN_LOADER=protected-local-only`) and the token in
`SENTINEL_OPENBAO_BOOTSTRAP_TOKEN`; this document intentionally provides no token
or token value. It sets TLS environment references, enables file audit and KV v2
at `secret`, installs the existing narrow `sentinel-read` policy, adds AppRole
with scoped Zabbix-read and StackStorm-notification-only roles, applies bounded
TTL/secret-ID limits, and revokes the bootstrap token with `token revoke -self`.
It does not generate or display AppRole secret IDs. Routine command output is
suppressed; sanitized operation names are emitted on failure, and root-token
cleanup reports only success/failure status. The token remains externally
supplied and is never printed. The helper is not idempotent and its execution
is not accepted until an operator independently verifies status, audit, KV,
policy, and AppRole state. No success claim is made by this document.

## TLS and audit checks

Provision certificates and keys through the approved operator process under the fixed `private/openbao/tls/` path; the preflight never generates or prints them. It rejects any `OPENBAO_TLS_DIR` override, including an empty one, and always validates that exact path to match Compose and the helper. The TLS directory itself must be exactly mode `0700`; this exact-mode rule does not apply to `openbao/config/` or `openbao/policies/`. Compose mounts the TLS directory at `/openbao/tls`. The fixed CA reference for init is `BAO_CACERT=/openbao/tls/ca.crt`; the fixed CA reference for configure is `BAO_CACERT=/openbao/tls/ca.crt`; the fixed CA reference for audit verification is `BAO_CACERT=/openbao/tls/ca.crt`; the fixed CA reference for KV verification is `BAO_CACERT=/openbao/tls/ca.crt`; the fixed CA reference for policy verification is `BAO_CACERT=/openbao/tls/ca.crt`; and the fixed CA reference for AppRole verification is `BAO_CACERT=/openbao/tls/ca.crt`. `server.key` must be owner-readable only (`0400` or `0600`); certificate files may use the documented non-writable readable modes. Verify chain and expiry before startup. Confirm the audit device is enabled and access-controlled. Do not use `-tls-skip-verify`; operator commands must set `BAO_ADDR` and `BAO_CACERT` through protected local handling. Audit, KV, policy, and AppRole outputs must be sanitized before retention or review.

## Backup and recovery

Back up the OpenBao data volume and audit records using the protected, encrypted procedure in `docs/recovery.md`. Recovery shares must be held separately from encrypted backups. Restore only into an isolated disposable instance and verify policy, audit, token expiry, and revocation before any production recovery.
