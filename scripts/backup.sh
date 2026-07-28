#!/usr/bin/env bash
# Create encrypted, local staging artifacts. This script does not back up OpenBao
# data: that operation requires a separately approved protected procedure.
set -eu

if [[ -z ${BASH_VERSION:-} ]]; then
  printf '%s\n' 'bash is required' >&2
  exit 1
fi

umask 077
if ! command -v readlink >/dev/null 2>&1; then
  printf '%s\n' 'readlink is required to resolve the physical backup script path' >&2
  exit 1
fi
SCRIPT_PATH=$(readlink -f -- "$0" 2>/dev/null) || SCRIPT_PATH=''
if [ -z "$SCRIPT_PATH" ] || [ ! -f "$SCRIPT_PATH" ]; then
  printf '%s\n' 'cannot resolve the physical backup script path with readlink -f; stop' >&2
  exit 1
fi
CDPATH=''
ROOT=$(cd -- "$(dirname -- "$SCRIPT_PATH")/.." && pwd -P) || {
  printf '%s\n' 'cannot resolve physical repository root' >&2
  exit 1
}

# Keep the dry-run planning metadata input fixed to this physical checkout. In
# particular, do not let an inherited working directory or environment override
# redirect tar to another tree.
if [ "${PLAN_METADATA_SOURCE+x}" = x ]; then
  printf '%s\n' 'PLAN_METADATA_SOURCE override is not accepted' >&2
  exit 1
fi
CURRENT_DIR=$(pwd -P) || {
  printf '%s\n' 'cannot resolve physical invocation directory' >&2
  exit 1
}
case "$CURRENT_DIR/" in
  "$ROOT/"|"$ROOT/"*) ;;
  *) printf '%s\n' 'backup must be invoked from within the physical repository root' >&2; exit 1 ;;
esac
PLAN_METADATA_SOURCE="$ROOT/monitoring/exports"
PLAN_METADATA_SOURCE_PHYSICAL=$(readlink -f -- "$PLAN_METADATA_SOURCE" 2>/dev/null) || PLAN_METADATA_SOURCE_PHYSICAL=''
if [ -z "$PLAN_METADATA_SOURCE_PHYSICAL" ] || [ ! -d "$PLAN_METADATA_SOURCE_PHYSICAL" ]; then
  printf '%s\n' 'fixed dry-run plan metadata source is missing or cannot be resolved physically' >&2
  exit 1
fi
if [ "$PLAN_METADATA_SOURCE_PHYSICAL" != "$PLAN_METADATA_SOURCE" ]; then
  printf '%s\n' 'fixed dry-run plan metadata source must not be a symlink or resolve outside the repository' >&2
  exit 1
fi
PLAN_METADATA_FILE="$PLAN_METADATA_SOURCE/plan.json"
PLAN_METADATA_FILE_PHYSICAL=$(readlink -f -- "$PLAN_METADATA_FILE" 2>/dev/null) || PLAN_METADATA_FILE_PHYSICAL=''
if [ -z "$PLAN_METADATA_FILE_PHYSICAL" ] || [ ! -f "$PLAN_METADATA_FILE_PHYSICAL" ] || [ "$PLAN_METADATA_FILE_PHYSICAL" != "$PLAN_METADATA_FILE" ]; then
  printf '%s\n' 'current dry-run plan metadata is missing, unsafe, or not a regular file' >&2
  exit 1
fi

if [ "${SENTINEL_NAMESPACE+x}" != x ] || [ -z "$SENTINEL_NAMESPACE" ]; then
  printf '%s\n' 'SENTINEL_NAMESPACE must be explicitly set' >&2
  exit 1
fi
if [ "${COMPOSE_PROJECT_NAME+x}" != x ] || [ -z "$COMPOSE_PROJECT_NAME" ]; then
  printf '%s\n' 'COMPOSE_PROJECT_NAME must be explicitly set' >&2
  exit 1
fi
case "$SENTINEL_NAMESPACE" in
  *[!a-zA-Z0-9_.-]*) printf '%s\n' 'SENTINEL_NAMESPACE has unsafe characters' >&2; exit 1 ;;
esac
case "$COMPOSE_PROJECT_NAME" in
  *[!a-zA-Z0-9_.-]*) printf '%s\n' 'COMPOSE_PROJECT_NAME has unsafe characters' >&2; exit 1 ;;
esac
if [ "$COMPOSE_PROJECT_NAME" != "$SENTINEL_NAMESPACE" ]; then
  printf '%s\n' 'COMPOSE_PROJECT_NAME must equal SENTINEL_NAMESPACE' >&2
  exit 1
fi
if [ "${BACKUP_DIR+x}" = x ]; then
  printf '%s\n' 'BACKUP_DIR override is not accepted; the physical repository backups directory is fixed' >&2
  exit 1
fi
BACKUP_DIR="$ROOT/backups"
: "${BACKUP_ENCRYPTION_RECIPIENT:?set a non-secret age recipient}"
: "${BACKUP_OFFSITE_URI:?set a non-secret off-host destination reference}"
: "${OPENBAO_BACKUP_REFERENCE:=openbao://protected-encrypted-procedure}"
: "${POSTGRES_USER:?set via protected environment}"
: "${POSTGRES_DB:?set via protected environment}"

if [ "${BACKUP_RETENTION_COUNT+x}" = x ] || [ "${BACKUP_RETENTION_PRUNE_APPROVAL+x}" = x ]; then
  printf '%s\n' 'backup retention/prune environment overrides are not accepted' >&2
  exit 1
fi

case "$POSTGRES_USER" in
  ''|[0-9]*|*[!a-zA-Z0-9_]*) printf '%s\n' 'POSTGRES_USER must match [A-Za-z_][A-Za-z0-9_]*' >&2; exit 1 ;;
esac
case "$POSTGRES_DB" in
  ''|[0-9]*|*[!a-zA-Z0-9_]*) printf '%s\n' 'POSTGRES_DB must match [A-Za-z_][A-Za-z0-9_]*' >&2; exit 1 ;;
esac
if [ "${#POSTGRES_USER}" -gt 63 ] || [ "${#POSTGRES_DB}" -gt 63 ]; then
  printf '%s\n' 'POSTGRES_USER and POSTGRES_DB must be at most 63 characters' >&2
  exit 1
fi

command -v bash >/dev/null 2>&1 || { printf '%s\n' 'bash is required' >&2; exit 1; }
command -v age >/dev/null 2>&1 || { printf '%s\n' 'age is required' >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { printf '%s\n' 'docker is required' >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'python3 is required' >&2; exit 1; }
command -v timeout >/dev/null 2>&1 || { printf '%s\n' 'GNU timeout is required' >&2; exit 1; }
command -v setsid >/dev/null 2>&1 || { printf '%s\n' 'setsid is required' >&2; exit 1; }
command -v ps >/dev/null 2>&1 || { printf '%s\n' 'ps is required' >&2; exit 1; }
if [[ ! -r /proc/self/stat ]]; then
  printf '%s\n' 'Linux /proc process identity is required' >&2
  exit 1
fi

# Fixed, non-overridable bounds. timeout sends TERM at the first bound and KILL
# five seconds later. The combined database/encryption pipeline gets 300 seconds;
# the metadata/encryption pipeline and manifest encryption get 60 seconds each.
TIMEOUT_KILL_AFTER=5s
PIPELINE_TIMEOUT=300s
ARCHIVE_TIMEOUT=60s

# These values become arguments or line-oriented manifest fields. Accept only
# bounded ASCII so an environment value cannot inject or split fields.
BACKUP_OFFSITE_URI=$BACKUP_OFFSITE_URI OPENBAO_BACKUP_REFERENCE=$OPENBAO_BACKUP_REFERENCE BACKUP_ENCRYPTION_RECIPIENT=$BACKUP_ENCRYPTION_RECIPIENT python3 - <<'PY' || {
import os
import sys

for name in ("BACKUP_OFFSITE_URI", "OPENBAO_BACKUP_REFERENCE", "BACKUP_ENCRYPTION_RECIPIENT"):
    value = os.environ[name]
    if len(value) > 1024 or any(ord(character) < 0x20 or ord(character) > 0x7e for character in value):
        sys.exit(1)
PY
  printf '%s\n' 'backup references and recipient must be at most 1024 printable single-line ASCII characters' >&2
  exit 1
}

if [ -L "$BACKUP_DIR" ]; then
  printf '%s\n' 'fixed backup destination must not be a symlink' >&2
  exit 1
fi
if [ ! -e "$BACKUP_DIR" ]; then
  mkdir -m 700 "$BACKUP_DIR" || {
    printf '%s\n' 'cannot create fixed backup destination' >&2
    exit 1
  }
fi
if [ ! -d "$BACKUP_DIR" ] || [ -L "$BACKUP_DIR" ]; then
  printf '%s\n' 'fixed backup destination must be a physical directory' >&2
  exit 1
fi
BACKUP_DIR_PHYSICAL=$(readlink -f -- "$BACKUP_DIR" 2>/dev/null) || BACKUP_DIR_PHYSICAL=''
if [ "$BACKUP_DIR_PHYSICAL" != "$BACKUP_DIR" ]; then
  printf '%s\n' 'fixed backup destination or an ancestor is not the expected physical path' >&2
  exit 1
fi
destination_uid=$(stat -c %u -- "$BACKUP_DIR") || {
  printf '%s\n' 'cannot inspect fixed backup destination owner' >&2
  exit 1
}
current_uid=$(id -u) || exit 1
if [ "$destination_uid" != "$current_uid" ] && [ "$destination_uid" != 0 ]; then
  printf '%s\n' 'fixed backup destination must be owned by the current user or root' >&2
  exit 1
fi
destination_mode=$(stat -c %A -- "$BACKUP_DIR") || {
  printf '%s\n' 'cannot inspect fixed backup destination mode' >&2
  exit 1
}
case "$destination_mode" in
  ?????w????|????????w?)
    printf '%s\n' 'fixed backup destination must not be group or world writable' >&2
    exit 1
    ;;
esac

lockdir="$BACKUP_DIR/.backup.lock"
if ! mkdir -m 700 "$lockdir" 2>/dev/null; then
  printf '%s\n' 'backup lock contention or incomplete lock metadata; fail closed and do not remove it automatically. Follow the protected stale-lock procedure in docs/backup.md; missing or partial metadata requires operator escalation' >&2
  exit 1
fi
workdir=''
active_pid=''
active_starttime=''
lock_owner_pid=$$
lock_owner_starttime=''
lock_started_utc=''
lock_run_identifier=''

write_lock_metadata() {
  {
    printf 'pid=%s\n' "$lock_owner_pid"
    printf 'proc_starttime=%s\n' "$lock_owner_starttime"
    printf 'started_utc=%s\n' "$lock_started_utc"
    printf 'run_identifier=%s\n' "$lock_run_identifier"
    if [[ -n $active_pid && -n $active_starttime ]]; then
      printf 'active_session_pid=%s\n' "$active_pid"
      printf 'active_session_proc_starttime=%s\n' "$active_starttime"
    fi
  } > "$lockdir/.metadata.tmp" || return 1
  chmod 600 "$lockdir/.metadata.tmp" || return 1
  mv -f -- "$lockdir/.metadata.tmp" "$lockdir/metadata"
}

proc_starttime() {
  local pid=$1
  python3 - "$pid" <<'PY'
import pathlib
import sys

pid = sys.argv[1]
if not pid.isascii() or not pid.isdigit() or pid == "0":
    raise SystemExit(1)
data = pathlib.Path("/proc", pid, "stat").read_text(encoding="ascii")
right = data.rfind(")")
if right < 0:
    raise SystemExit(1)
fields = data[right + 2:].split()
if len(fields) <= 19 or not fields[19].isdigit():
    raise SystemExit(1)
print(fields[19])
PY
}

active_identity_matches() {
  local observed_start observed_pgid
  [[ -n $active_pid && -n $active_starttime ]] || return 1
  observed_start=$(proc_starttime "$active_pid" 2>/dev/null) || return 1
  [[ $observed_start == "$active_starttime" ]] || return 1
  observed_pgid=$(ps -o pgid= -p "$active_pid" 2>/dev/null) || return 1
  observed_pgid=${observed_pgid//[[:space:]]/}
  [[ $observed_pgid == "$active_pid" ]]
}

terminate_active_session() {
  local count=0
  [[ -n $active_pid ]] || return 0
  if active_identity_matches; then
    kill -TERM -- "-$active_pid" 2>/dev/null || true
    while active_identity_matches && (( count < 5 )); do
      sleep 1
      ((count += 1))
    done
    if active_identity_matches; then
      kill -KILL -- "-$active_pid" 2>/dev/null || true
    fi
  fi
  wait "$active_pid" 2>/dev/null || true
  active_pid=''
  active_starttime=''
}

# Start a fresh process group in a stopped state so its Linux starttime and PGID
# can be recorded before any producer runs. The fixed script is passed as one
# argument; validated values are exported and expanded only by the inner Bash.
run_bounded() {
  local duration=$1 pipeline_script=$2 status attempt observed_pgid
  setsid bash -c 'kill -STOP "$$"; exec "$@"' sentinel-backup-session \
    timeout --signal=TERM --kill-after="$TIMEOUT_KILL_AFTER" "$duration" \
    bash -o pipefail -c "$pipeline_script" &
  active_pid=$!
  active_starttime=''
  attempt=0
  while (( attempt < 100 )); do
    active_starttime=$(proc_starttime "$active_pid" 2>/dev/null) || active_starttime=''
    observed_pgid=$(ps -o pgid= -p "$active_pid" 2>/dev/null) || observed_pgid=''
    observed_pgid=${observed_pgid//[[:space:]]/}
    if [[ -n $active_starttime && $observed_pgid == "$active_pid" ]]; then
      break
    fi
    sleep 0.01
    ((attempt += 1))
  done
  if [[ -z $active_starttime || $observed_pgid != "$active_pid" ]]; then
    terminate_active_session
    return 1
  fi
  if ! write_lock_metadata; then
    terminate_active_session
    return 1
  fi
  kill -CONT -- "-$active_pid" 2>/dev/null || {
    terminate_active_session
    return 1
  }
  set +e
  wait "$active_pid"
  status=$?
  set -e
  # A normal foreground wait reaped the session. Clear identity so EXIT cleanup
  # can never target a subsequently reused PID.
  active_pid=''
  active_starttime=''
  write_lock_metadata || return 1
  return "$status"
}

cleanup() {
  terminate_active_session
  if [ -n "$workdir" ] && [ -d "$workdir" ]; then
    rm -rf -- "$workdir"
  fi
  if [ -d "$lockdir" ]; then
    rm -f -- "$lockdir/metadata" "$lockdir/.metadata.tmp"
    rmdir -- "$lockdir" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
workdir=$(mktemp -d "${BACKUP_DIR}/.staging.XXXXXXXXXX") || {
  printf '%s\n' 'cannot create private backup staging directory' >&2
  exit 1
}

# Validate all current desired-state inputs, then verify the metadata checksum
# and exact equivalence of a staged copy to the current desired-state plan. The
# verified bytes are then stable while the database dump runs. `rollback` is an
# inert review command and performs no infrastructure mutation.
python3 "$ROOT/scripts/sentinel.py" validate >/dev/null || {
  printf '%s\n' 'current desired-state validation failed; no backup was attempted' >&2
  exit 1
}
cp "$PLAN_METADATA_FILE" "$workdir/plan.json" || {
  printf '%s\n' 'dry-run plan metadata staging failed; no backup was attempted' >&2
  exit 1
}
python3 "$ROOT/scripts/sentinel.py" rollback "$workdir/plan.json" >/dev/null || {
  printf '%s\n' 'dry-run plan integrity or current-state verification failed; no backup was attempted' >&2
  exit 1
}

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
set_suffix=${workdir##*.staging.}
set_name="sentinel-backup-${timestamp}-${set_suffix}"
lock_owner_starttime=$(proc_starttime "$$") || {
  printf '%s\n' 'cannot record backup process starttime from /proc' >&2
  exit 1
}
lock_started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ) || exit 1
lock_run_identifier=$set_name
write_lock_metadata || {
  printf '%s\n' 'cannot record complete backup lock metadata' >&2
  exit 1
}
final_set="$BACKUP_DIR/$set_name"
postgres_name="postgres.dump.age"
plan_metadata_name="dry-run-plan-metadata.tar.age"
manifest_name="manifest.txt.age"

# The plaintext dump exists only in this pipe. One timeout bounds and terminates
# the entire producer/encryptor process group, and pipefail observes both sides.
export ROOT SENTINEL_NAMESPACE POSTGRES_USER POSTGRES_DB BACKUP_ENCRYPTION_RECIPIENT
PIPELINE_OUTPUT="$workdir/$postgres_name"
export PIPELINE_OUTPUT
# Expansion is deliberately deferred to the fixed inner Bash script.
# shellcheck disable=SC2016
if ! run_bounded "$PIPELINE_TIMEOUT" 'docker compose --project-name "$SENTINEL_NAMESPACE" --project-directory "$ROOT" -f "$ROOT/compose.yaml" --env-file /dev/null exec -T postgres pg_dump --format=custom --no-password --host=/var/run/postgresql --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" | age -r "$BACKUP_ENCRYPTION_RECIPIENT" -o "$PIPELINE_OUTPUT" -'; then
  printf '%s\n' 'PostgreSQL backup failed; no artifact was published' >&2
  exit 1
fi

# Only the generated, sanitized dry-run plan metadata is included. This is not a
# Zabbix configuration export or backup, and no live API call is performed here.
PIPELINE_OUTPUT="$workdir/$plan_metadata_name"
PIPELINE_DIRECTORY="$workdir"
export PIPELINE_OUTPUT PIPELINE_DIRECTORY
# shellcheck disable=SC2016  # Expansion is deferred to the fixed inner Bash.
if ! run_bounded "$ARCHIVE_TIMEOUT" 'tar -C "$PIPELINE_DIRECTORY" -cf - plan.json | age -r "$BACKUP_ENCRYPTION_RECIPIENT" -o "$PIPELINE_OUTPUT" -'; then
  printf '%s\n' 'Dry-run plan metadata archival failed; no artifact was published' >&2
  exit 1
fi

checksum_file() {
  local checksum
  checksum=$(python3 - "$1" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if path.stat().st_size <= 0:
    raise SystemExit(1)
digest = hashlib.sha256()
with path.open("rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
print(digest.hexdigest())
PY
  ) || return 1
  [[ $checksum =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$checksum"
}
postgres_sha=$(checksum_file "$workdir/$postgres_name") || {
  printf '%s\n' 'PostgreSQL ciphertext checksum failed validation; no backup set was published' >&2
  exit 1
}
plan_metadata_sha=$(checksum_file "$workdir/$plan_metadata_name") || {
  printf '%s\n' 'planning metadata ciphertext checksum failed validation; no backup set was published' >&2
  exit 1
}
cat > "$workdir/manifest.txt" <<EOF
format=sentinel-backup-v2
set_name=$set_name
created_utc=$timestamp
postgres_artifact=$postgres_name
postgres_sha256=$postgres_sha
dry_run_plan_metadata_artifact=$plan_metadata_name
dry_run_plan_metadata_sha256=$plan_metadata_sha
dry_run_plan_metadata_source=$PLAN_METADATA_FILE
dry_run_plan_metadata_scope=validated-current-planning-metadata-not-zabbix-configuration
openbao_backup_reference=$OPENBAO_BACKUP_REFERENCE
offhost_destination=$BACKUP_OFFSITE_URI
restore_test_status=not-run
restore_test_scope=isolated-disposable-instance-with-synthetic-secrets
EOF
PIPELINE_OUTPUT="$workdir/$manifest_name"
PIPELINE_INPUT="$workdir/manifest.txt"
export PIPELINE_OUTPUT PIPELINE_INPUT
# shellcheck disable=SC2016  # Expansion is deferred to the fixed inner Bash.
run_bounded "$ARCHIVE_TIMEOUT" 'age -r "$BACKUP_ENCRYPTION_RECIPIENT" -o "$PIPELINE_OUTPUT" "$PIPELINE_INPUT"' || {
  printf '%s\n' 'Manifest encryption failed; no backup set was published' >&2
  exit 1
}
rm -f "$workdir/manifest.txt" "$workdir/plan.json"
COMPLETE_MARKER='sentinel-backup-complete-v1'
COMPLETE_MARKER_BYTES=$(printf '%s\n' "$COMPLETE_MARKER" | wc -c)
printf '%s\n' "$COMPLETE_MARKER" > "$workdir/.sentinel-complete-set"

is_complete_set() {
  candidate=$1
  if [ ! -d "$candidate" ] || [ -L "$candidate" ] \
    || [ ! -f "$candidate/.sentinel-complete-set" ] || [ -L "$candidate/.sentinel-complete-set" ] \
    || [ "$(sed -n '1p' "$candidate/.sentinel-complete-set" 2>/dev/null)" != "$COMPLETE_MARKER" ] \
    || [ "$(wc -c < "$candidate/.sentinel-complete-set" 2>/dev/null)" -ne "$COMPLETE_MARKER_BYTES" ] \
    || [ ! -s "$candidate/postgres.dump.age" ] || [ -L "$candidate/postgres.dump.age" ] \
    || [ ! -s "$candidate/dry-run-plan-metadata.tar.age" ] || [ -L "$candidate/dry-run-plan-metadata.tar.age" ] \
    || [ ! -s "$candidate/manifest.txt.age" ] || [ -L "$candidate/manifest.txt.age" ]; then
    return 1
  fi
  for member in "$candidate"/* "$candidate"/.[!.]* "$candidate"/..?*; do
    [ -e "$member" ] || [ -L "$member" ] || continue
    case "$member" in
      "$candidate/postgres.dump.age"|"$candidate/dry-run-plan-metadata.tar.age"|"$candidate/manifest.txt.age"|"$candidate/.sentinel-complete-set") ;;
      *) return 1 ;;
    esac
  done
  return 0
}

# Verify the exact, nonempty member set and marker before publication.  Flush
# each encrypted artifact and the marker, then the staging directory metadata.
# Python is already a required dependency and exposes fsync portably enough for
# this Linux commissioning scaffold.
is_complete_set "$workdir" || {
  printf '%s\n' 'staged backup set is incomplete, empty, or has unexpected members; no set was published' >&2
  exit 1
}
python3 - "$workdir" "$postgres_name" "$plan_metadata_name" "$manifest_name" <<'PY' || {
import os
import sys

directory = sys.argv[1]
for name in (*sys.argv[2:], ".sentinel-complete-set"):
    fd = os.open(os.path.join(directory, name), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
  printf '%s\n' 'backup set durability sync failed; no set was published' >&2
  exit 1
}

# Linux renameat2(RENAME_NOREPLACE) is required: unlike an existence check plus
# rename, it atomically rejects a target that appears concurrently. Fail closed
# when the syscall or flag is unavailable.
python3 - "$workdir" "$final_set" <<'PY' || {
import ctypes
import errno
import os
import sys

source, target = map(os.fsencode, sys.argv[1:])
libc = ctypes.CDLL(None, use_errno=True)
try:
    renameat2 = libc.renameat2
except AttributeError:
    print("Linux renameat2(RENAME_NOREPLACE) is unavailable; no set was published", file=sys.stderr)
    sys.exit(1)
renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
renameat2.restype = ctypes.c_int
if renameat2(-100, source, -100, target, 1) != 0:  # AT_FDCWD, RENAME_NOREPLACE
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        print("backup set publication collision; no set was published", file=sys.stderr)
    elif error in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
        print("Linux renameat2(RENAME_NOREPLACE) is unavailable; no set was published", file=sys.stderr)
    else:
        print(f"atomic no-replace backup set publication failed: errno {error}", file=sys.stderr)
    sys.exit(1)
PY
  printf '%s\n' 'atomic no-replace backup set publication failed' >&2
  exit 1
}
workdir=''
python3 - "$BACKUP_DIR" <<'PY' || {
import os
import sys

fd = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
  printf '%s\n' 'backup directory durability sync failed after publication; published set may exist' >&2
  exit 1
}

printf '%s\n' "Ciphertext artifact set published atomically to $final_set (off-host copy required: $BACKUP_OFFSITE_URI)"
printf '%s\n' 'Decryptability and recoverability are unverified. OpenBao data/audit backup remains a separately approved encrypted procedure; restore test status is not-run.'
