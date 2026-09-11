#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 || ! -f "$1" ]]; then
    echo "Usage: infra/verify-restore.sh BACKUP.dump" >&2
    exit 1
fi
for secops_expected in "${SECOPS_EXPECTED_FINDINGS:-}" "${SECOPS_EXPECTED_COMMENTS:-}" \
    "${SECOPS_EXPECTED_USERS:-}" "${SECOPS_EXPECTED_SESSIONS:-}" "${SECOPS_EXPECTED_SAVED_VIEWS:-}"; do
    if [[ -n "$secops_expected" && ! "$secops_expected" =~ ^[0-9]+$ ]]; then
        echo "Expected restore row counts must be nonnegative integers" >&2
        exit 1
    fi
done
secops_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
secops_env="${SECOPS_ENV_FILE:-${secops_root}/.env}"
secops_compose=(docker compose --env-file "$secops_env" -f "$secops_root/infra/docker-compose.yml")
secops_restore_db="secops_restore_check_$(date -u +%Y%m%d%H%M%S)_${RANDOM}"
secops_created=false
cleanup() {
    if [[ "$secops_created" == true ]]; then
        "${secops_compose[@]}" exec -T postgres sh -c \
            'exec dropdb -U "$POSTGRES_USER" -- "$1"' sh "$secops_restore_db"
    fi
}
trap cleanup EXIT
"${secops_compose[@]}" exec -T postgres sh -c \
    'exec createdb -U "$POSTGRES_USER" -- "$1"' sh "$secops_restore_db"
secops_created=true
"${secops_compose[@]}" exec -T postgres sh -c \
    'exec pg_restore -U "$POSTGRES_USER" --dbname="$1" --exit-on-error --no-owner --no-privileges' \
    sh "$secops_restore_db" < "$1"
secops_counts="$("${secops_compose[@]}" exec -T postgres sh -c \
    'exec psql -U "$POSTGRES_USER" --dbname="$1" --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align --field-separator=: --command="SELECT (SELECT count(*) FROM findings), (SELECT count(*) FROM comments);"' \
    sh "$secops_restore_db")"
if [[ ! "$secops_counts" =~ ^[0-9]+:[0-9]+$ ]]; then
    echo "Restore row-count verification did not produce valid counts" >&2
    exit 1
fi
secops_findings="${secops_counts%%:*}"
secops_comments="${secops_counts##*:}"
if [[ -n "${SECOPS_EXPECTED_FINDINGS:-}" && "$secops_findings" != "$SECOPS_EXPECTED_FINDINGS" ]] \
    || [[ -n "${SECOPS_EXPECTED_COMMENTS:-}" && "$secops_comments" != "$SECOPS_EXPECTED_COMMENTS" ]]; then
    echo "Restored row counts do not match the expected backup contents" >&2
    exit 1
fi
echo "Restored findings: $secops_findings; comments: $secops_comments"
# Identity tables were introduced in 0.2. A restored 0.1 archive may omit them;
# report zero without issuing a SELECT against an absent relation.
for secops_table in users user_sessions saved_views; do
    case "$secops_table" in
        users) secops_expected="${SECOPS_EXPECTED_USERS:-}" ;;
        user_sessions) secops_expected="${SECOPS_EXPECTED_SESSIONS:-}" ;;
        saved_views) secops_expected="${SECOPS_EXPECTED_SAVED_VIEWS:-}" ;;
    esac
    secops_exists="$("${secops_compose[@]}" exec -T postgres sh -c \
        'exec psql -U "$POSTGRES_USER" --dbname="$1" --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align --command="$2"' \
        sh "$secops_restore_db" "SELECT to_regclass('public.$secops_table') IS NOT NULL;")"
    if [[ "$secops_exists" == t ]]; then
        secops_count="$("${secops_compose[@]}" exec -T postgres sh -c \
            'exec psql -U "$POSTGRES_USER" --dbname="$1" --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align --command="$2"' \
            sh "$secops_restore_db" "SELECT count(*) FROM public.$secops_table;")"
    elif [[ "$secops_exists" == f ]]; then
        secops_count=0
    else
        echo "Restore table-existence verification did not produce a valid result" >&2
        exit 1
    fi
    if [[ ! "$secops_count" =~ ^[0-9]+$ ]] || [[ -n "$secops_expected" && "$secops_count" != "$secops_expected" ]]; then
        echo "Restored $secops_table count does not match the expected backup contents" >&2
        exit 1
    fi
    echo "Restored $secops_table: $secops_count (table present: $secops_exists)"
done
echo "Restore completed in an isolated database; the active application database was not changed."
