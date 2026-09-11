#!/usr/bin/env bash
set -euo pipefail
umask 077

secops_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
secops_output="${1:-${secops_root}/backups/secops-$(date -u +%Y%m%dT%H%M%SZ).dump}"
secops_env="${SECOPS_ENV_FILE:-${secops_root}/.env}"
secops_file="${SECOPS_COMPOSE_FILE:-${secops_root}/infra/docker-compose.yml}"
secops_compose=(docker compose --env-file "$secops_env" -f "$secops_file")

if [[ -e "$secops_output" ]]; then
    echo "Refusing to replace an existing backup file" >&2
    exit 1
fi
mkdir -p -- "$(dirname -- "$secops_output")"
secops_temporary="$(mktemp "${secops_output}.tmp.XXXXXX")"
trap 'rm -f -- "$secops_temporary"' EXIT
"${secops_compose[@]}" exec -T postgres sh -c \
    'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --lock-wait-timeout=30s' > "$secops_temporary"
"${secops_compose[@]}" exec -T postgres pg_restore --list < "$secops_temporary" > /dev/null
# Link atomically without replacing another backup created concurrently.
ln -- "$secops_temporary" "$secops_output"
echo "Backup written to $secops_output"
echo "Run infra/verify-restore.sh against this file to validate a complete restore."
