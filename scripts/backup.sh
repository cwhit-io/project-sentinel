#!/usr/bin/env sh
set -eu
: "${BACKUP_DIR:=./backups}"
: "${BACKUP_ENCRYPTION_RECIPIENT:?set a protected age recipient; no secret is accepted here}"
command -v age >/dev/null 2>&1 || { printf '%s\n' 'age is required for encrypted backups' >&2; exit 1; }
mkdir -p "$BACKUP_DIR"
umask 077
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
plain="$BACKUP_DIR/zabbix-$timestamp.dump"
encrypted="$plain.age"
docker compose exec -T postgres pg_dump -Fc -U "${POSTGRES_USER:?set via protected environment}" "${POSTGRES_DB:-zabbix}" > "$plain"
age -r "$BACKUP_ENCRYPTION_RECIPIENT" -o "$encrypted" "$plain"
rm -f "$plain"
printf '%s\n' "Encrypted PostgreSQL backup written to $encrypted"
printf '%s\n' 'OpenBao volume and audit backup require the separate protected procedure in docs/recovery.md.'
