#!/bin/sh
# Static/local prerequisite check only. This script never contacts OpenBao or creates files.
set -u
if ! command -v readlink >/dev/null 2>&1; then
    printf '%s\n' 'preflight: required tool not found: readlink (cannot resolve the physical checkout path).' >&2
    exit 1
fi
SCRIPT_PATH=$(readlink -f -- "$0" 2>/dev/null) || SCRIPT_PATH=''
if [ -z "$SCRIPT_PATH" ] || [ ! -f "$SCRIPT_PATH" ]; then
    printf '%s\n' 'preflight: cannot resolve the physical script path with readlink -f; stop.' >&2
    exit 1
fi
CDPATH=''
ROOT=$(cd -- "$(dirname -- "$SCRIPT_PATH")/.." && pwd -P) || {
    printf '%s\n' 'preflight: cannot resolve the physical repository root; stop.' >&2
    exit 1
}
TLS_DIR="$ROOT/private/openbao/tls"
if [ "${OPENBAO_TLS_DIR+x}" = x ]; then
    printf '%s\n' 'preflight: OPENBAO_TLS_DIR override is not accepted; use the fixed repository private/openbao/tls path.' >&2
    exit 1
fi
CONFIG_DIR="$ROOT/openbao/config"
POLICY_DIR="$ROOT/openbao/policies"
failures=0
fail() { printf '%s\n' "preflight: $*" >&2; failures=$((failures + 1)); }

validate_openbao_port() {
    case "$1" in
        ''|*[!0-9]*) return 1;;
    esac
    [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 65535 ] 2>/dev/null
}

check_openbao_listener() {
    port=$1
    command -v ss >/dev/null 2>&1 || return 2
    listeners=$(ss -H -ltn "sport = :$port" 2>/dev/null) || return 3
    [ -z "$listeners" ]
}

# Check every fixed component before any metadata or contents below it are
# inspected. ROOT itself is already physical (derived from readlink -f and
# pwd -P); none of the security-sensitive descendants may redirect traversal.
check_fixed_path() {
    [ -L "$1" ] && fail "security-sensitive path component must not be a symlink: $1"
}
for fixed_path in \
    "$ROOT/private" \
    "$ROOT/private/openbao" \
    "$TLS_DIR" \
    "$ROOT/openbao" \
    "$CONFIG_DIR" \
    "$POLICY_DIR" \
    "$TLS_DIR/ca.crt" \
    "$TLS_DIR/server.crt" \
    "$TLS_DIR/server.key"
do
    check_fixed_path "$fixed_path"
done
if [ "$failures" -ne 0 ]; then
    printf '%s\n' "preflight: $failures security-sensitive path component(s) unsafe; stop." >&2
    exit 1
fi

check_dir() {
    path=$1
    if [ ! -d "$path" ]; then fail "missing directory: $path (this check will not create it)"; return; fi
    [ -L "$path" ] && fail "directory must not be a symlink: $path"
    if [ ! -r "$path" ] || [ ! -x "$path" ]; then
        fail "directory is not accessible: $path"
    fi
    owner=$(stat -c '%u' "$path" 2>/dev/null) || { fail "cannot inspect ownership: $path"; return; }
    mode=$(stat -c '%a' "$path" 2>/dev/null) || { fail "cannot inspect permissions: $path"; return; }
    uid=$(id -u 2>/dev/null) || { fail 'cannot determine current user'; return; }
    [ "$owner" = 0 ] || [ "$owner" = "$uid" ] || fail "untrusted owner: $path"
    case "$mode" in
        ''|*[!0-7]*) fail "cannot inspect permissions: $path"; return;;
    esac
    mode_bits=$((0$mode))
    [ $((mode_bits & 18)) -eq 0 ] || fail "group/world writable TLS directory: $path"
}

check_tls_dir() {
    path=$1
    check_dir "$path"
    if [ ! -d "$path" ] || [ -L "$path" ]; then
        return
    fi
    mode=$(stat -c '%a' "$path" 2>/dev/null) || { fail "cannot inspect permissions: $path"; return; }
    [ "$mode" = 700 ] || fail "TLS directory must have mode 0700: $path"
}

check_file() {
    name=$1; kind=$2; path="$TLS_DIR/$name"
    if [ ! -f "$path" ]; then fail "missing TLS file: $path (this check will not generate it)"; return; fi
    [ -L "$path" ] && { fail "TLS file must not be a symlink: $path"; return; }
    [ -r "$path" ] || fail "TLS file is not readable: $path"
    owner=$(stat -c '%u' "$path" 2>/dev/null) || { fail "cannot inspect ownership: $path"; return; }
    mode=$(stat -c '%a' "$path" 2>/dev/null) || { fail "cannot inspect permissions: $path"; return; }
    uid=$(id -u 2>/dev/null) || { fail 'cannot determine current user'; return; }
    [ "$owner" = 0 ] || [ "$owner" = "$uid" ] || fail "untrusted owner: $path"
    # %a is normally a three-digit mode.  Only reject write bits belonging to
    # group/other; owner-write is expected for the private key (for example,
    # 600).  Do not use a broad pattern here: [2367] in the owner position is
    # not a group/world write bit.
    case "$mode" in
        ??[2367]|?[2367]?) fail "group/world writable TLS file: $path";;
    esac
    case "$kind:$mode" in
        # Private keys must not be group-readable.  Certificates may use the
        # wider, non-writable modes listed below.
        key:400|key:600|cert:400|cert:440|cert:444|cert:600|cert:640|cert:644) : ;;
        *) fail "unsafe permissions for $kind: $path";;
    esac
}

printf '%s\n' 'OpenBao preflight: local prerequisites only; no initialization, authentication, service start, or network contact.'
check_tls_dir "$TLS_DIR"; check_dir "$CONFIG_DIR"; check_dir "$POLICY_DIR"
check_file ca.crt cert; check_file server.crt cert; check_file server.key key
command -v grep >/dev/null 2>&1 || fail 'required tool not found: grep'
command -v docker >/dev/null 2>&1 || fail 'required tool not found: docker'
if command -v docker >/dev/null 2>&1; then
    docker compose version >/dev/null 2>&1 || fail 'required Docker Compose plugin is unavailable'
fi
command -v stat >/dev/null 2>&1 || fail 'required tool not found: stat'
command -v id >/dev/null 2>&1 || fail 'required tool not found: id'
command -v openssl >/dev/null 2>&1 || fail 'required tool not found: openssl'

if command -v openssl >/dev/null 2>&1; then
    for cert in ca.crt server.crt; do
        path="$TLS_DIR/$cert"
        [ -f "$path" ] || continue
        openssl x509 -in "$path" -noout -checkend 0 >/dev/null 2>&1 || fail "certificate is invalid or expired: $path"
    done
    if [ -f "$TLS_DIR/server.crt" ] && [ -f "$TLS_DIR/server.key" ]; then
        openssl pkey -in "$TLS_DIR/server.key" -passin pass: -noout >/dev/null 2>&1 || fail "private key is invalid: $TLS_DIR/server.key"
        san=$(openssl x509 -in "$TLS_DIR/server.crt" -noout -ext subjectAltName 2>/dev/null) || san=''
        printf '%s\n' "$san" | grep -Eq '(^|[,[:space:]])DNS:openbao([,[:space:]]|$)' || fail 'server certificate lacks DNS SAN openbao'
        # Compare canonical DER SubjectPublicKeyInfo values, rather than RSA
        # moduli, so EC and other OpenSSL-supported key types work too.  Only
        # the digest is retained; OpenSSL output and key material are hidden.
        cert_hash=$(openssl x509 -in "$TLS_DIR/server.crt" -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null) || cert_hash=''
        key_hash=$(openssl pkey -in "$TLS_DIR/server.key" -passin pass: -pubout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null) || key_hash=''
        if [ -z "$cert_hash" ] || [ "$cert_hash" != "$key_hash" ]; then
            fail 'server key does not match server certificate'
        fi
    fi
    if [ -f "$TLS_DIR/ca.crt" ] && [ -f "$TLS_DIR/server.crt" ]; then
        openssl verify -CAfile "$TLS_DIR/ca.crt" "$TLS_DIR/server.crt" >/dev/null 2>&1 || fail 'server certificate does not chain to the configured CA'
    fi
fi

validate_compose_name() {
    # Docker Compose project-name grammar: start with lowercase alphanumeric;
    # every remaining character is lowercase alphanumeric, underscore, or hyphen.
    case "$1" in
        ''|[!abcdefghijklmnopqrstuvwxyz0123456789]*|*[!abcdefghijklmnopqrstuvwxyz0123456789_-]*) return 1;;
    esac
    return 0
}

if [ "${SENTINEL_NAMESPACE+x}" = x ]; then
    namespace=$SENTINEL_NAMESPACE
else
    namespace=sentinel
fi
collision_checks=1
if ! validate_compose_name "$namespace"; then
    fail 'SENTINEL_NAMESPACE must match Docker Compose project-name grammar: lowercase alphanumeric first, then lowercase alphanumeric, underscore, or hyphen only'
    collision_checks=0
fi
# Compose's project label is the container-side identity for this namespace.
# Require it explicitly: relying on Compose's directory-derived project name
# could make collision checks inspect the wrong namespace.
if [ "${COMPOSE_PROJECT_NAME+x}" != x ]; then
    fail 'COMPOSE_PROJECT_NAME must be explicitly set and equal SENTINEL_NAMESPACE before collision checks'
    collision_checks=0
    project=''
else
    project=$COMPOSE_PROJECT_NAME
    if ! validate_compose_name "$project"; then
        fail 'COMPOSE_PROJECT_NAME must match Docker Compose project-name grammar: lowercase alphanumeric first, then lowercase alphanumeric, underscore, or hyphen only'
        collision_checks=0
    fi
    if [ "$project" != "$namespace" ]; then
        fail 'COMPOSE_PROJECT_NAME must equal SENTINEL_NAMESPACE before collision checks'
        collision_checks=0
    fi
fi
docker_ready=0
if [ "$collision_checks" -eq 1 ] && command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
        docker_ready=1
    else
        fail 'Docker daemon/API is unavailable; cannot inspect namespace resources'
    fi
fi

resource_state() {
    kind=$1; resource=$2
    # Establish absence from a successful list, never from an inspect error.
    if [ "$kind" = network ]; then
        if ! matches=$(docker network ls --filter "name=^${resource}$" --quiet 2>/dev/null); then return 2; fi
    else
        if ! matches=$(docker volume ls --filter "name=^${resource}$" --quiet 2>/dev/null); then return 2; fi
    fi
    [ -n "$matches" ] || return 1
    docker "$kind" inspect "$resource" >/dev/null 2>&1 || return 2
    return 0
}

if [ "$collision_checks" -eq 1 ] && [ "$docker_ready" -eq 1 ]; then
    if ! containers=$(docker ps -a --filter "label=com.docker.compose.project=$project" --quiet 2>/dev/null); then
        fail "Docker API error while inspecting Compose project containers: $project"
    elif [ -n "$containers" ]; then
        fail "Compose project already has containers; choose a unique SENTINEL_NAMESPACE/COMPOSE_PROJECT_NAME: $project"
    fi
    for resource in "$namespace-database" "$namespace-application" "$namespace-monitoring" "$namespace-secrets" "$namespace-openbao-operator" "$namespace-zabbix-operator" "$namespace-postgres-data" "$namespace-openbao-data" "$namespace-openbao-audit"; do
        resource_state network "$resource"; network_state=$?
        resource_state volume "$resource"; volume_state=$?
        case "$network_state:$volume_state" in
            0:*|*:0) fail "named resource already exists; choose a unique SENTINEL_NAMESPACE: $resource";;
            2:*|*:2) fail "Docker API error while inspecting namespace resource: $resource";;
        esac
    done
fi

# Keep this final so the host-listener observation is as close as this no-start
# preflight can place it to the separately approved Compose startup. Any listener,
# including a wildcard bind, is a collision. There is no wildcard port bypass.
if [ "${OPENBAO_PORT+x}" = x ]; then
    openbao_port=$OPENBAO_PORT
else
    openbao_port=18200
fi
if ! validate_openbao_port "$openbao_port"; then
    fail 'OPENBAO_PORT must be a numeric value from 1 through 65535'
else
    check_openbao_listener "$openbao_port"
    listener_state=$?
    if [ "$listener_state" -ne 0 ]; then
        case "$listener_state" in
            1) fail "OPENBAO_PORT already has a host TCP listener: $openbao_port";;
            2) fail 'required tool not found: ss (cannot inspect OPENBAO_PORT listeners)';;
            *) fail "ss failed while inspecting OPENBAO_PORT: $openbao_port";;
        esac
    fi
fi

if [ "$failures" -ne 0 ]; then
    printf '%s\n' "preflight: $failures prerequisite(s) missing or unsafe; stop." >&2; exit 1
fi
printf '%s\n' 'preflight: local prerequisites are present; this does not approve or perform commissioning.'
exit 0
