#!/bin/sh
# Protected commissioning helper.  Deliberately never starts Compose services.
set -eu

if ! command -v readlink >/dev/null 2>&1; then
    printf '%s\n' 'bootstrap: required tool not found: readlink (cannot resolve the physical checkout path).' >&2
    exit 1
fi
SCRIPT_PATH=$(readlink -f -- "$0" 2>/dev/null) || SCRIPT_PATH=''
if [ -z "$SCRIPT_PATH" ] || [ ! -f "$SCRIPT_PATH" ]; then
    printf '%s\n' 'bootstrap: cannot resolve the physical script path with readlink -f; stop.' >&2
    exit 1
fi
CDPATH=''
ROOT=$(cd -- "$(dirname -- "$SCRIPT_PATH")/.." && pwd -P) || {
    printf '%s\n' 'bootstrap: cannot resolve the physical repository root; stop.' >&2
    exit 1
}
if [ "${OPENBAO_TLS_DIR+x}" = x ]; then
    printf '%s\n' 'bootstrap: OPENBAO_TLS_DIR override is not accepted; use the fixed private/openbao/tls path' >&2
    exit 1
fi
TLS_DIR="$ROOT/private/openbao/tls"

usage() {
    printf '%s\n' "usage: $0 init|configure" >&2
    exit 64
}

[ "$#" -eq 1 ] || usage
phase=$1
case "$phase" in init|configure) ;; *) usage ;; esac

# These are intentionally inconvenient, human-readable custody confirmations.
[ "${SENTINEL_OPENBAO_BOOTSTRAP_ACK:-}" = "I_UNDERSTAND_PROTECTED_OPENBAO_BOOTSTRAP" ] || {
    printf '%s\n' 'bootstrap: protected bootstrap acknowledgement is required' >&2; exit 1;
}
[ "${SENTINEL_RECOVERY_CUSTODY_ACK:-}" = "I_UNDERSTAND_OPERATOR_RECOVERY_CUSTODY" ] || {
    printf '%s\n' 'bootstrap: operator recovery-custody acknowledgement is required' >&2; exit 1;
}
[ "${SENTINEL_SYNTHETIC_LAB_ACK:-}" = "I_UNDERSTAND_SYNTHETIC_ONLY_LAB_SCOPE" ] || {
    printf '%s\n' 'bootstrap: synthetic-only disposable-lab acknowledgement is required' >&2; exit 1;
}
[ "${SENTINEL_OPENBAO_PREFLIGHT_CONFIRMED:-}" = "I_CONFIRM_OPENBAO_PREFLIGHT_PASSED" ] || {
    printf '%s\n' 'bootstrap: operator must confirm the completed no-init preflight' >&2
    exit 1
}
if [ "${SENTINEL_NAMESPACE+x}" != x ] || [ "${COMPOSE_PROJECT_NAME+x}" != x ]; then
    printf '%s\n' 'bootstrap: SENTINEL_NAMESPACE and COMPOSE_PROJECT_NAME must be explicitly equal' >&2
    exit 1
elif [ "$SENTINEL_NAMESPACE" != "$COMPOSE_PROJECT_NAME" ]; then
    printf '%s\n' 'bootstrap: SENTINEL_NAMESPACE and COMPOSE_PROJECT_NAME must be explicitly equal' >&2
    exit 1
fi

# Check the exact local TLS inputs. The operator confirmation above is a
# deliberate one-way gate: preflight must run before Compose resources start,
# so rerunning it here would reject the resources it intentionally found.
if [ ! -d "$TLS_DIR" ] || [ -L "$TLS_DIR" ]; then
    printf '%s\n' 'bootstrap: fixed TLS directory is missing or symlinked' >&2
    exit 1
fi
[ "$(stat -c '%a' "$TLS_DIR" 2>/dev/null)" = 700 ] || {
    printf '%s\n' 'bootstrap: fixed TLS directory must have mode 0700' >&2
    exit 1
}
for tls_file in ca.crt server.crt server.key; do
    if [ ! -f "$TLS_DIR/$tls_file" ] || [ -L "$TLS_DIR/$tls_file" ]; then
        printf '%s\n' "bootstrap: protected TLS path is missing or symlinked: $tls_file" >&2
        exit 1
    fi
done

if [ "$phase" = init ]; then
    printf '%s\n' 'WARNING: the attached terminal will receive recovery shares and initial root material.' >&2
    printf '%s\n' 'Secure that terminal output manually; OpenCode must not receive or retain it.' >&2
    # No pipe, capture, redirect, parsing, or logging: recovery output stays attached
    # to the operator terminal.  This command also intentionally does not unseal.
    exec docker compose --env-file /dev/null --project-directory "$ROOT" -f "$ROOT/compose.yaml" --profile secrets exec \
        -e BAO_ADDR=https://openbao:8200 \
        -e BAO_CACERT=/openbao/tls/ca.crt \
        openbao bao operator init -key-shares=3 -key-threshold=2 -format=json
fi

if [ "${SENTINEL_OPENBAO_BOOTSTRAP_TOKEN+x}" != x ]; then
    printf '%s\n' 'bootstrap: protected externally supplied bootstrap token is required' >&2
    exit 1
elif [ -z "$SENTINEL_OPENBAO_BOOTSTRAP_TOKEN" ]; then
    printf '%s\n' 'bootstrap: protected externally supplied bootstrap token is required' >&2
    exit 1
fi
[ "${SENTINEL_OPENBAO_BOOTSTRAP_TOKEN_LOADER:-}" = "protected-local-only" ] || {
    printf '%s\n' 'bootstrap: protected-loader marker is required' >&2
    exit 1
}

# Keep the supplied token out of command arguments and clean the local shell copy.
BAO_TOKEN=$SENTINEL_OPENBAO_BOOTSTRAP_TOKEN
export BAO_TOKEN
run_bao() {
    docker compose --env-file /dev/null --project-directory "$ROOT" -f "$ROOT/compose.yaml" --profile secrets exec -T \
        -e BAO_ADDR=https://openbao:8200 \
        -e BAO_CACERT=/openbao/tls/ca.crt \
        -e BAO_TOKEN \
        openbao bao "$@"
}

revocation_done=0
cleanup() {
    status=$?
    if [ "${revocation_done:-0}" -eq 0 ]; then
        if run_bao token revoke -self >/dev/null 2>&1; then
            printf '%s\n' 'bootstrap: token revocation cleanup succeeded' >&2
        else
            printf '%s\n' 'bootstrap: token revocation cleanup failed' >&2
        fi
    fi
    unset BAO_TOKEN SENTINEL_OPENBAO_BOOTSTRAP_TOKEN SENTINEL_OPENBAO_BOOTSTRAP_TOKEN_LOADER
    trap - 0 1 2 3 15
    [ "$status" -eq 0 ] || exit "$status"
}
trap cleanup 0 1 2 3 15

run_operation() {
    operation=$1
    shift
    if run_bao "$@" >/dev/null 2>&1; then return 0; fi
    printf '%s\n' "bootstrap: $operation failed" >&2
    return 1
}

# Suppress output that could contain sensitive material, but retain a sanitized
# operation name when a configuration operation fails.
run_operation 'audit enable' audit enable file file_path=/openbao/audit/audit.log
run_operation 'KV enable' secrets enable -path=secret kv-v2
run_operation 'sentinel-read policy write' policy write sentinel-read /openbao/policies/sentinel-read.hcl
run_operation 'notification-only policy write' policy write sentinel-stackstorm-notification-only - <<'POLICY'
path "secret/data/stackstorm/zabbix-webhook-hmac" {
  capabilities = ["read"]
}
POLICY
run_operation 'AppRole auth enable' auth enable approle
run_operation 'Zabbix-read AppRole write' write auth/approle/role/zabbix-read \
    token_policies=sentinel-read token_ttl=1h token_max_ttl=4h \
    secret_id_ttl=24h secret_id_num_uses=1
run_operation 'notification-only AppRole write' write auth/approle/role/stackstorm-notification-only \
    token_policies=sentinel-stackstorm-notification-only token_ttl=1h token_max_ttl=4h \
    secret_id_ttl=24h secret_id_num_uses=1
# Secret IDs are deliberately neither generated nor displayed here.
if run_bao token revoke -self >/dev/null 2>&1; then
    revocation_done=1
else
    printf '%s\n' 'bootstrap: final bootstrap-token revocation failed' >&2
    exit 1
fi
