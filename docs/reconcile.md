# Reconcile Operator Runbook

This runbook describes the closed `sentinel reconcile` workflow introduced on
2026-07-28. The mocked-only evidence remains authoritative. On 2026-07-29
the live-discovery code path was wired but **not** executed against the real
Zabbix in this session; per [`scope.md`](scope.md), TLS, PostgreSQL backup,
OpenBao, Zabbix, and StackStorm are operator-managed.

The reconcile path is the **only** Sentinel mechanism that can ever call a
write client. `sentinel apply` remains hard-disabled.

## Live-discovery wiring (2026-07-29)

The `--source live-discovery` branch is wired but was not executed against
the real Zabbix in this session. The factories are:

- `automation.zabbix.credentials.build_file_provider(state_dir, handle_id)`
  reads `state_dir/config.yaml`, looks up
  `credential_handles.<handle_id>.path`, expands `~` to the running user's
  home, and validates owner-uid, mode `0600`, non-symlink, size
  `(0, 4096]`, and non-empty after newline stripping via
  `FileCredentialProvider`. Every failure raises `CredentialFileError` with
  one of the closed sanitized messages; no path contents are reflected.
- `automation.reconciliation.cli.build_read_client(handle_id, state_dir)`
  calls `build_file_provider`, builds a `ReadCredentialHandle`, sources the
  endpoint from `state_dir/config.yaml` under the new top-level
  `target_endpoint` key (defaulting to `https://sentinel.bhm.li/api_jsonrpc.php`),
  and assembles a `JsonRpcTransport` with trust id `cloudflare-tls`,
  `timeout_seconds=10`, `max_request_bytes=65536`, and
  `max_response_bytes=1048576`. The endpoint default points at the real
  Zabbix at `sentinel.bhm.li`.
- `scripts/sentinel.py` imports `build_read_client` and passes it as
  `read_client_factory` to `reconcile_main`. The write path is intentionally
  unwired; any `--apply-if-signed` invocation exits with `EXIT_INTERNAL`
  until a separate bounded probe-write integration is approved.

The operator may execute the live command from a host that satisfies the
prerequisites:

```
python3 scripts/sentinel.py reconcile \
    --source live-discovery \
    --scope public-uptime \
    --credential-handle zabbix-read \
    --state-dir ~/sentinel-state \
    --approval-key ~/.config/sentinel/trusted-approvers/approval.ed25519
```

Without `--apply-if-signed` the command writes a plan under
`~/sentinel-state/run-<unix-ms>-public-uptime/` and exits `0`. With
`--apply-if-signed` the write path is still unavailable in this milestone
and the command exits `70` (internal) after the signature check.

## Prerequisites

- A POSIX user with a writable home directory.
- An operator-created Ed25519 SSH keypair at
  `~/.config/sentinel/trusted-approvers/approval.ed25519` (private,
  mode `0600`) and `~/.config/sentinel/trusted-approvers/approval.ed25519.pub`.
  Sentinel **does not** generate or rotate this key.
- A state directory at `~/sentinel-state/` mode `0700`. Sentinel creates it
  on first reconcile and refuses to use anything that is not owner-controlled
  mode `0700`.
- A `~/sentinel-state/config.yaml` mode `0600` containing the literal
  reference `approval_key: /home/<user>/.config/sentinel/trusted-approvers/approval.ed25519`,
  or the equivalent `--approval-key` flag.
- A `credential_handles.zabbix-read.path` entry in `~/sentinel-state/config.yaml`
  pointing to a token file owned by the running user, mode `0600`, not a
  symlink, size in `(0, 4096]`, and non-empty after newline stripping.
- Inventory, monitoring, and route YAML that passes `sentinel validate`.

## State directory layout

```
~/sentinel-state/
├── config.yaml                 # mode 0600
├── auto-sign-enabled           # optional one-time marker (mode 0600)
└── run-<unix-ms>-<scope>/      # one directory per reconcile attempt
    ├── desired.json            # filtered, sanitized desired state
    ├── observed.json           # sanitized snapshot
    ├── plan.json               # plan that was approved and applied
    ├── plan.json.sig           # detached Ed25519 SSH signature
    ├── receipt.json            # sanitized probe-write receipt
    └── signing-template.json   # closed metadata for the user
```

Run directories are mode `0700`. All JSON files are mode `0600`. Sentinel
rejects the state directory unless it is owned by the running user and
mode `0700`; nothing inside it is ever read or written without first
verifying ownership and mode.

## Manual-sign-once, then auto-sign workflow

1. **Validate**: `python3 scripts/sentinel.py validate` must succeed.
2. **First manual approval**: run the reconcile command, manually sign the
   generated plan with `ssh-keygen -Y sign`, then run `sentinel reconcile
   --apply-if-signed` again with the signature present.
3. **Enable auto-sign**: create the `~/sentinel-state/auto-sign-enabled`
   marker file (mode `0600`) after you have verified the first manual
   approval.
4. **Future runs**: `sentinel reconcile --apply-if-signed` will auto-sign
   subsequent plans as long as the marker exists and the approval key is
   available.
5. **Revoke auto-sign**: remove `~/sentinel-state/auto-sign-enabled`. The
   next run will require another manual signature.

## What Sentinel can and cannot do

Sentinel **can**:
- Validate inventory, monitoring, and route YAML.
- Diff desired state against a snapshot from a read-only Zabbix client.
- Render a deterministic plan and a plain-English summary.
- Sign the plan automatically when the marker is present.
- Open the **exact** `WriteZabbixClient` against the **exact** write
  transport and apply the plan in order.
- Re-verify the post-state via the read client.
- Write a sanitized receipt to `~/sentinel-state/runs/<id>/receipt.json`.

Sentinel **cannot** (and never will, in this milestone):
- Run a live reconcile without operator execution. The live-discovery
  factories are wired but the operator must invoke the documented command;
  Sentinel does not auto-call the real Zabbix.
- Connect to the live Zabbix endpoint without a configured read-token file
  that passes the `FileCredentialProvider` owner/mode/non-symlink/size
  guards. The transport and client types are exact and refuse any
  credential path that fails validation.
- Read or write real credentials outside the configured token file. The
  read factory opens only the path resolved from
  `credential_handles.<handle_id>.path`; the write factory does not exist.
- Apply the plan without a verified signature. `verify_detached` raises
  `PermissionError` for any invalid payload, signature, key, identity, or
  namespace mismatch.
- Run `sentinel apply`. That command is hard-disabled before parsing,
  signing, or any I/O.
- Delete a host. The probe policy declares `host.delete`, `httptest.delete`,
  and `item.delete` as `executor: none`. No delete executor exists.
- Persist StackStorm receipts. StackStorm is a trusted upstream platform;
  the receipt path remains disabled.

## Where things go

| Action | Path |
| --- | --- |
| Plan written (dry-run or pre-apply) | `~/sentinel-state/runs/<id>/plan.json` |
| Detached SSH signature | `~/sentinel-state/runs/<id>/plan.json.sig` |
| Sanitized post-apply receipt | `~/sentinel-state/runs/<id>/receipt.json` |
| Sanitized desired state | `~/sentinel-state/runs/<id>/desired.json` |
| Sanitized observed state | `~/sentinel-state/runs/<id>/observed.json` |
| Signing template (user-facing) | `~/sentinel-state/runs/<id>/signing-template.json` |

The `signing-template.json` document contains the exact
`ssh-keygen -Y sign -f <key> -n sentinel-reconcile <plan_path>` command
the operator runs. The principal is `sentinel-reconcile` and the namespace
is `sentinel-reconcile`.

## Failure modes

The CLI emits stable exit codes:

| Exit | Meaning |
| --- | --- |
| `0` | success |
| `1` | validation |
| `2` | sanitization |
| `3` | read-only preflight violation |
| `4` | scope isolation |
| `5` | awaiting approval |
| `64` | argument misuse |
| `70` | internal |

Failure responses never print payload, signature, key contents, or paths.
The signer public key path is read from `config.yaml` or the
`--approval-key` flag; it is never reflected back to the operator.

## Manual sign command

The plan is signed with one command:

```
ssh-keygen -Y sign -f ~/.config/sentinel/trusted-approvers/approval.ed25519 \
    -n sentinel-reconcile <plan_path>
```

The signature is written to `<plan_path>.sig` mode `0600`. Sentinel
re-verifies the signature before every apply. A tampered plan, a
mismatched signature, a missing principal, or an invalid namespace all
raise `PermissionError` and the run stops with exit code `5`.

## Evidence

The mocked test suite at `tests/test_reconcile.py` and
`tests/test_http_inventory_schema.py` exercises the full reconcile pipe
end-to-end against synthetic keys and in-memory clients. The static
evidence file is `docs/evidence/reconcile-20260728.md`.