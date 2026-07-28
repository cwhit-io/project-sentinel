# Disposable commissioning lab

This record is non-operational and synthetic-only. The completed bounded milestone
is sealed compatibility evidence, not bootstrap or production acceptance.
Real infrastructure, credentials, secret values, recovery material, and production
remediation remain prohibited.

The old internal-only project `sentinel-overnight-openbao` was independently
verified uninitialized and sealed. Its exact container, network, and named data
and audit volumes were removed; the TLS bind source was preserved. The fresh
project `sentinel-night-openbao2` then passed preflight and started with the
corrected topology. It was running healthy with restart count 0, and independent
status reported `initialized=false` and `sealed=true`.

Effective publication was exactly `127.0.0.1:18200->8200`. A CA-verified loopback
health request returned HTTP 200, while a non-loopback host connection was
refused. Networks were exactly the dedicated non-internal
`sentinel-night-openbao2-openbao-operator` and internal
`sentinel-night-openbao2-secrets`, each with exactly one member.

The OpenBao Compose redesign is a static compatibility fix only. Direct binary
invocation and removal of obsolete `disable_mlock` progressed the prior attempt to
TLS loading, where capability-dropped root could not traverse/read the
operator-owned mode-`0700` TLS directory and mode-`0600` key. Compose does not
weaken those permissions: after dropping all capabilities it adds only `IPC_LOCK`
and `DAC_READ_SEARCH`, not `DAC_OVERRIDE`. `DAC_READ_SEARCH` is a broad
process-wide capability that bypasses DAC read/search checks and is accepted only
for isolated commissioning; it remains prohibited for production. This design is
not production hardening or runtime acceptance.

Effective inspection confirmed numeric user `0:0`, capability drop `ALL`, only
`DAC_READ_SEARCH` and `IPC_LOCK` added, read-only root, no-new-privileges,
read-only config/policy/TLS binds, expected named data/audit volumes, and bounded
tmpfs mounts. No initialization, unseal, authentication, helper, credentials, or
recovery material occurred. The fresh project was fully torn down and TLS was
preserved. Root plus broad `DAC_READ_SEARCH` and ordinary bridge NAT remain
production blockers.

The independent Zabbix core/transport milestone separately passed reviewer audit:
PostgreSQL, server, web, and synthetic agent were healthy at restart count 0;
web/API and server were loopback-only; API version was `7.0.14`;
server-to-agent `agent.ping` was `1`; host-to-agent access was rejected; and
PostgreSQL and the agent were not published. Registration, dashboards/data,
alerts, authenticated API use, and apply were deliberately not performed.

Restored-application technical checks observed a fresh isolated internal network,
the restored selected aggregate, a ready server process, internal web HTTP `200`,
and no published ports. The independent validator run is **FAILED** because it
used unrestricted `docker inspect` and exposed synthetic environment fields in
private output. Values are intentionally not repeated. This handling incident
means the milestone is not accepted; a future separately approved run must use
safe field-scoped inspection and undergo independent revalidation.

Final cleanup removed all disposable source/restore/application containers,
project networks, named volumes, and explicitly inventoried anonymous volumes.
Unrelated volumes and images and commissioning TLS were preserved. No real
credentials or recovery material were used.

A separate bounded registry check successfully pulled all five exact configured
`name:tag@sha256` image references. This records point-in-time registry
resolvability and immutable references only. It does not verify publisher identity,
signature, attestation, provenance, continuing availability, runtime health, or
production acceptance.

Any future start or bootstrap requires separate approval; this completed evidence
does not authorize either action.

Earlier cleanup evidence also remains valid: prior anonymous volume IDs
`f217b92076e00129830d5f2c94d8603bdda55d7baf15c91ca901241a4aaa2b38` and
`ee87fa7623506bec8657f2f02f88ae364757b0da3b2eebdaee38fcdbbcd5309f` are absent,
and commissioning TLS metadata remains.

Use a unique disposable `SENTINEL_NAMESPACE` for each lab and set
`COMPOSE_PROJECT_NAME` to that same value. Compose records the project in the
`com.docker.compose.project` container label; preflight fails if matching
containers, explicitly named networks, or volumes already exist, and Docker
API errors fail closed. The default `sentinel` is safe only after that check.
Do not reuse a namespace until teardown is confirmed.

The `secret://...` values in `.env.example` are metadata references, not
Compose interpolation syntax. Standard Compose cannot dereference them. A
protected secret-loader/injection step is required before any runtime starts;
resolved secret values must never be committed, logged, or placed in commands.
All commissioning Compose commands use `--env-file /dev/null` so an ambient
repository `.env` is not consumed. The operator must export the required
`POSTGRES_USER` and `POSTGRES_PASSWORD` interpolation variables as disposable
synthetic values in the protected shell before rendering or starting Compose;
this runbook intentionally supplies no values.

## Staged phases

1. **Old internal-only project teardown — PASSED.** `sentinel-overnight-openbao` was independently verified sealed/uninitialized; its exact runtime container, network, and named data/audit volumes were removed, with TLS preserved.
2. **Fresh preflight and sealed corrected-topology startup — BOUNDED PASS.** `sentinel-night-openbao2` passed preflight, ran healthy at restart 0, independently reported sealed/uninitialized, published exactly to loopback, returned CA-verified HTTP 200 there, and refused a non-loopback host connection. Exact network membership and effective hardening matched the evidence above.
3. **Fresh-project teardown — PASSED.** `sentinel-night-openbao2` was fully removed and TLS was preserved. No bootstrap action or secret handling occurred.

The command shape retained below is documentation only and is **not currently
authorized for execution**:

```sh
ROOT=$(pwd -P) # run at the reviewed repository root
export SENTINEL_NAMESPACE='operator-selected-disposable-name'
export COMPOSE_PROJECT_NAME="$SENTINEL_NAMESPACE"
"$ROOT/scripts/openbao-preflight.sh"
docker compose --project-directory "$ROOT" -f "$ROOT/compose.yaml" --project-name "$COMPOSE_PROJECT_NAME" --env-file /dev/null --profile secrets up -d openbao
```

Set `ROOT` with `pwd -P` only while at the reviewed repository root. The
preflight itself independently resolves the physical checkout root from its
script path. Do not use generic relative startup examples: the absolute
project-directory and Compose file bind both steps to the same checkout.

Both namespace variables must be equal and match Docker Compose project-name
grammar: lowercase alphanumeric first, then only lowercase alphanumeric,
underscore, or hyphen. Empty values, uppercase, dots, leading punctuation, and
spaces are rejected.

The fixed `private/openbao/tls/` directory must be mode `0700`; the exact-mode
requirement is not imposed on the config or policy directories. TLS file checks
remain in force. `OPENBAO_TLS_DIR` must be unset: preflight rejects every override,
including an empty one, and checks only the fixed path used by Compose and the
helper.
Only an unset `OPENBAO_PORT` defaults to `18200`; an explicitly empty value is
invalid, and every set value otherwise must be numeric in `1..65535`.
Preflight requires `ss` and, as its final prerequisite check immediately before
startup, rejects any existing host TCP listener on the selected port, including
wildcard listeners.

Do not set the helper confirmation marker or run the guarded helper. Bootstrap
requires a future separate protected authorization and custody plan.
4. **Least-privilege synthetic secret rotation — BLOCKED / NOT TESTED.** Create only disposable identities and synthetic values; demonstrate TTL, renewal, revocation, and rotation without exposing values.
5. **Zabbix core/agent transport — INDEPENDENT REVIEW PASS.** Four healthy/restart-0 containers, loopback web/API/server, API `7.0.14`, server-to-agent ping `1`, host-agent rejection, and no database/agent publication were recorded. This does not include registration or monitoring apply.
6. **Dashboard/data verification — BLOCKED / NOT TESTED.** Capture sanitized evidence of agent availability, collected data, discovery, and dashboard rendering.
7. **Notification-only StackStorm receipt — BLOCKED / NOT TESTED.** Every notification route is explicitly `enabled: false`. Policy references to those routes preserve desired intent, but delivery is blocked. The `sentinel-hmac-v1` framing and replay contract/vector tests reject Transfer-Encoding, require one exact Content-Length, require HTTP/2 proxy equivalence, and define event-level replay identity as source identity plus event ID. Re-signing the same event does not create a new identity. The contract retains it through the inclusive maximum of first-receipt-plus-window-plus-future-skew and signed-timestamp-plus-window. These static contract/vector tests, signature helpers, payload `max_bytes`, and forbidden-field declarations are not runtime enforcement. A future separately approved test must demonstrate authenticated receipt, framing/boundary/replay/payload rejection, and receipt of an approved event without executing remediation or changing infrastructure.
8. **Alert recovery — BLOCKED / NOT TESTED.** Safely induce and recover a synthetic condition, recording both transitions and timestamps.
9. **PostgreSQL exact restore — ATTESTED, NOT DURABLY ACCEPTED.** The current selected aggregate was observed, but repeatability, encryption, and production recovery remain blocked.
10. **Restored application — FAILED / NOT ACCEPTED.** Technical observations cannot be accepted because the validator run exposed synthetic environment fields through unrestricted inspection. Revalidate safely in a future run.
11. **Encrypted backup/production restore — BLOCKED / NOT TESTED.** The unexecuted script describes one atomically published ciphertext set containing a PostgreSQL dump, validated dry-run planning metadata, and an honest manifest, not a Zabbix configuration backup; a sanitized live Zabbix export needs a separately implemented/verified path and is blocked. It neither requires nor archives an apply receipt. Static mocked tests exercise identifier and manifest-metadata validation, exact dump arguments, destination, process-group identity, partial/stale-lock handling, pipeline timeout/failure, checksum failure, cleanup ordering, rollback-verification failure, collision, no-replace rename failure, zero-byte rejection, exact layout, and fsync ordering without Docker, age, or credentials. Under `setsid timeout --signal=TERM --kill-after=5s` and `bash -o pipefail`, `pg_dump | age` is bounded at 300 seconds while `tar | age` and synchronous manifest `age` are bounded at 60 seconds. The script preserves every set and rejects retention/prune overrides; retirement is a separate protected operator procedure only after decryption and isolated restore verification. A contended lock is never auto-removed; exact adjudication is in `docs/backup.md`, and missing/partial metadata requires escalation. Handled cleanup identity-checks and reaps before staging/lock removal, but SIGKILL/power loss can still leave stale state. Extended/default ACLs are not inspected or enforced. Fsync/rename cannot guarantee durability on every filesystem or storage stack, and no decryptability or plaintext-integrity claim exists without protected decryption and restore. Verify real encrypted artifacts and an isolated repeatable restore only in a future protected run; keep recovery shares separate from backups.

## Acceptance evidence

Acceptance requires phase-linked timestamps, reviewed command records without secret output, Compose/profile and network scope, health checks, Zabbix availability/data and dashboard evidence, StackStorm notification receipt with proof of no action, alert firing/recovery, encrypted backup/isolated restore results, and teardown confirmation. Missing tools, unavailable runtime, skipped checks, or unverified claims remain blocked—not passes.

Do not connect to production or external hosts, register real agents, use real credentials or secrets, initialize OpenBao outside the approved protected lab, generate recovery material outside approved custody, or enable remediation.
