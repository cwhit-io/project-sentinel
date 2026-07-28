# Backup boundary

This is an unexecuted protected procedure, not backup or recovery evidence.

`scripts/backup.sh` is designed to produce encrypted artifacts for a PostgreSQL
logical dump, sanitized dry-run planning metadata, and a manifest. The planning
metadata artifact is honestly named `dry-run-plan-metadata.tar.age`, contains
only `monitoring/exports/plan.json`, and is labeled in the manifest as planning
metadata rather than Zabbix configuration. It cannot restore Zabbix
configuration. Because apply is hard-disabled, `apply-receipt.json` is neither a
prerequisite nor an archived file.

Before the database dump begins, the script requires current desired-state
validation, stages the plan, and verifies that stable copy's unkeyed integrity
checksum and exact equivalence to current desired state through the inert
review-only rollback command. Only those verified staged bytes are archived.
Missing, symlinked, malformed, stale, or integrity-invalid plan metadata fails
closed. The checksum detects accidental or unreviewed modification; it is
not authenticity, approval, or proof that any configuration was applied.

The destination is fixed to the physical checkout's `backups/` directory; an
environment override is rejected. Before staging, the script rejects a symlinked
destination, a destination that does not resolve to that physical path, ownership
other than the current user or root, and group/world write permission. This is
what “access-controlled backup” means in this baseline; it is not an assumption
about the host. Extended/default ACLs, MAC policy, mount options, and remote
filesystem permissions are **not inspected or enforced** by the script. An atomic
`mkdir` lock rejects concurrent runs. Its `metadata` file records the Bash PID,
Linux `/proc/<pid>/stat` starttime, UTC start, and set/run identifier, but no
secret material. While a bounded child group is active, the file also records its
session PID and `/proc` starttime; normal reaping clears those active fields. It is
removed after an ordinary handled exit. On contention the
script fails closed and never automatically removes the lock. A missing, empty,
partial, malformed, or contradictory metadata file cannot establish process
identity and requires protected operator escalation; it must not be guessed at or
automatically repaired. SIGKILL, kernel failure, and power loss bypass traps and
can leave lock/staging state. Cleanup is therefore not guaranteed.

### Exact stale-lock adjudication procedure

This is a future protected operator procedure, not authorization to run it here.
Work from the reviewed physical checkout and do **not** delete anything initially.

1. Preserve and inspect only `backups/.backup.lock/metadata`. Require exactly one
   nonempty value for `pid`, numeric `proc_starttime`, UTC, and `run_identifier`.
   Missing/partial/malformed metadata stops the procedure for escalation. If
   `active_session_pid` and `active_session_proc_starttime` are present, apply the
   same strict identity checks to that session; one without the other is partial.
2. For a still-present `/proc/<pid>/stat`, parse field 22 after the final `)` and
   compare it exactly with `proc_starttime`; also require `ps -o pgid= -p <pid>`
   to equal `<pid>`. A mismatch may be PID reuse: do not signal it and escalate.
3. Using field-scoped `ps -eo pid=,ppid=,pgid=,lstart=,comm=,args=`, account for
   every member of that PGID. Escalate if any command is not from this bounded
   chain: `setsid`, `timeout --signal=TERM --kill-after=5s`, `bash -o pipefail`,
   `docker compose ... exec -T postgres pg_dump`, `tar`, or `age`. Do not rely on
   a command-name substring alone; PID, starttime, PGID, run ID, ownership, and
   staging paths must agree.
4. Before declaring the run absent, use the same reviewed absolute Compose
   binding and project identity to perform a field-scoped, read-only
   container-side process listing for `pg_dump` in `postgres`. Do not use
   unrestricted inspection and do not print environment fields. If Compose is
   unavailable, the container cannot be identified unambiguously, or any
   container-side `pg_dump` remains, escalate and retain the lock.

   ```sh
   docker compose --project-name "$SENTINEL_NAMESPACE" --project-directory "$ROOT" -f "$ROOT/compose.yaml" --env-file /dev/null exec -T postgres ps -eo pid=,ppid=,pgid=,comm=,args=
   ```

   This command is inspection-only and must be run only in an approved protected
   environment with `ROOT` and the namespace bound as in the backup procedure.
5. If the recorded identity still matches, terminate the **whole recorded process
   group**, TERM first, wait/reap for at most five seconds, re-verify the same
   PID/starttime/PGID identity, and only then KILL the group if needed. Never
   signal a mismatched or unverified PID. Recheck host processes and the
   container-side `pg_dump` listing after reaping.
6. Verify each `.staging.*` path is a non-symlink directory under the fixed
   physical `backups/` directory and owned by the expected account. Unexpected
   ownership or contents requires escalation. Only after every check succeeds may
   the operator remove that run's adjudicated staging directory and then remove
   only `backups/.backup.lock`. Record the decision and evidence.

The database user and database name must each match the conservative
`[A-Za-z_][A-Za-z0-9_]*` grammar and be at most 63 characters. The exact dump
options are custom format, no password prompt, Unix socket host
`/var/run/postgresql`, and explicit `--username=...` and `--dbname=...` forms. Before
publication, the script requires exactly three nonempty encrypted artifacts and
the exact completion marker, with no extra members. It uses Python `os.fsync` on
each encrypted artifact and marker and on the staged set directory, performs one
same-filesystem Linux `renameat2(RENAME_NOREPLACE)` directory rename, and then
fsyncs `backups/`. Publication fails closed if that syscall/flag is unavailable.

Bash, Linux `/proc`, `ps`, `setsid`, and GNU `timeout` are required. The
`pg_dump | age` pipeline has one fixed 300-second process-group bound; the
`tar | age` pipeline and synchronous manifest `age` each have a fixed 60-second
process-group bound. They run through `bash -o pipefail` under `setsid timeout
--signal=TERM --kill-after=5s`, so producer or consumer failure fails the whole
operation. The parent records the session-leader PID and `/proc` starttime before
continuing it. On a handled signal, cleanup verifies both starttime and PGID,
TERMs then KILLs the whole group if still identical, waits/reaps, and only then
removes staging and lock state. Normal completion waits/reaps and clears the
active identity. This avoids intentionally signaling a reused PID; it cannot make
SIGKILL, kernel failure, or power loss cleanup reliable. There are no FIFOs and no
separately backgrounded `age` consumers.

This procedure creates no live or sanitized Zabbix configuration export. Such an
export requires a separately implemented and verified path and is blocked.

These calls improve crash durability but cannot guarantee it: filesystem and
kernel support, network/overlay filesystems, storage-controller or device write
caches, hardware failure, and host power-loss behavior remain outside this
scaffold. Atomic rename does not prove durable media persistence.

The script never retires or prunes sets and rejects retention/prune environment
overrides. Every published set is preserved. Retirement is a separate protected
operator procedure and may be considered only after protected decryption and a
successful isolated restore have been verified; it must not be automated here.

The line-oriented manifest values supplied by `BACKUP_OFFSITE_URI` and
`OPENBAO_BACKUP_REFERENCE` are limited to 1024 printable single-line ASCII
characters. Control characters and newlines fail closed.

Execution remains blocked pending a protected environment, approved non-secret
encryption recipient and off-host references, synthetic database access,
reviewed custody, and isolated restore verification. OpenBao data/audit backup is
a separate approved encrypted procedure; recovery material must never be stored
with backups. Nonempty ciphertext, hashes, fsync success, and publication do not
prove decryptability or plaintext integrity. Those claims require protected
decryption and an isolated restore using approved custody; neither was performed.
