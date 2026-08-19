#!/usr/bin/env bash
# Move Kubernetes Secrets between the cluster and a local directory, with
# a diff you have to agree to first.
#
# Secrets are the one part of this deployment Flux does not manage: they
# cannot live in a public repo, so they exist only in the cluster. That
# makes them easy to lose and easy to change by accident, which is what
# this is for -- a way to take a copy, put one back, and see exactly what
# would change before it does.
#
# VALUES ARE NOT PRINTED BY DEFAULT. A changed key shows as a pair of
# SHA-256 fingerprints, which tells you something changed without putting
# a DKIM private key into your scrollback or a screenshot. Pass
# --show-values when you genuinely need to see the contents.
#
# With no secret named, every secret in the namespace is synced --
# service-account tokens and Helm release blobs excluded, since those
# belong to the cluster rather than to us.
#
#   scripts/secrets-sync.sh download                    # all of them
#   scripts/secrets-sync.sh download postbud-dkim
#   scripts/secrets-sync.sh upload   postbud-dkim --show-values
#
# One file per key, named for the key. That is the same shape
# `kubectl create secret generic --from-file` expects, so a directory
# taken from here can be fed straight back by hand if this script is
# unavailable.
set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
usage: secrets-sync.sh <download|upload> [secret] [options]

  with no secret named, every secret in the namespace is synced

  download   cluster -> local directory
  upload     local directory -> cluster

options:
  --dir DIR        local directory (default: secrets/<secret>)
  --namespace NS   kubernetes namespace (default: $POSTBUD_NAMESPACE or postbud)
  --show-values    show the actual values in the diff, not fingerprints
  --yes            skip the confirmation prompt
USAGE
    exit 2
}

[ $# -ge 1 ] || usage
ACTION=$1; shift
SECRET=""
case "${1:-}" in ""|--*) ;; *) SECRET=$1; shift ;; esac

DIR=""
NS="${POSTBUD_NAMESPACE:-postbud}"
SHOW_VALUES=0
ASSUME_YES=0

while [ $# -gt 0 ]; do
    case "$1" in
        --dir) DIR=${2:?--dir needs a value}; shift 2 ;;
        --namespace) NS=${2:?--namespace needs a value}; shift 2 ;;
        --show-values) SHOW_VALUES=1; shift ;;
        --yes) ASSUME_YES=1; shift ;;
        *) usage ;;
    esac
done

command -v kubectl >/dev/null || { echo "kubectl not found" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }

# A local copy of a secret must never be committable. If we are inside a
# work tree and the target is not ignored, stop -- the alternative is
# finding a DKIM key in a public repo later.
guard_gitignored() {
    git rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 0
    if ! git check-ignore -q "$1" 2>/dev/null; then
        echo "refusing: '$1' is not gitignored, and secrets must never be committable." >&2
        echo "add it to .gitignore first." >&2
        exit 1
    fi
}

fingerprint() { openssl dgst -sha256 -binary < "$1" | openssl base64 -A | cut -c1-12; }

# Pull the live secret into $1, one decoded file per key. Absent secret is
# not an error: it is an empty directory, so `upload` can create one.
fetch_cluster_into() {
    local secret=$1 into=$2
    mkdir -p "$into"
    # A secret that does not exist yet is an EMPTY set of keys, not an
    # error -- that is exactly the state `upload` starts from when
    # creating one. Without the `|| true`, pipefail turns a first-time
    # upload into a silent exit.
    # The braces are load-bearing. `A || true | while ...` parses as
    # `A || (true | while ...)`, because `|` binds tighter than `||` --
    # so on the happy path, where kubectl SUCCEEDS, the `||` short-circuits
    # and the decode loop never runs at all. The keys land on stdout
    # instead of in files, every diff sees an empty cluster, and every
    # key reads as new. Grouping puts the fallback inside the pipeline's
    # left-hand side, where it was meant to be.
    { kubectl -n "$NS" get secret "$secret" -o go-template='{{range $k,$v := .data}}{{$k}} {{$v}}{{"\n"}}{{end}}' 2>/dev/null || true; } \
    | while read -r key b64; do
        [ -n "${key:-}" ] || continue
        printf '%s' "$b64" | openssl base64 -d -A > "$into/$key"
    done
}

# Render the difference between two directories: $1 is what exists now,
# $2 is what would replace it.
render_diff() {
    local from=$1 to=$2 changed=0
    local keys
    keys=$( { ls -1 "$from" 2>/dev/null; ls -1 "$to" 2>/dev/null; } | sort -u )
    # Nothing on either side is nothing to do, which is the same answer
    # as "identical": return success so the caller reports no changes.
    [ -n "$keys" ] || { echo "  (both sides empty)"; return 0; }

    while IFS= read -r key; do
        [ -n "$key" ] || continue
        if [ ! -f "$from/$key" ]; then
            printf '  + %-34s (new)\n' "$key"; changed=1
        elif [ ! -f "$to/$key" ]; then
            printf '  - %-34s (removed)\n' "$key"; changed=1
        elif cmp -s "$from/$key" "$to/$key"; then
            printf '    %-34s (unchanged)\n' "$key"
        else
            changed=1
            if [ "$SHOW_VALUES" -eq 1 ]; then
                echo "  ~ $key"
                diff -u "$from/$key" "$to/$key" | sed 's/^/      /' || true
            else
                printf '  ~ %-34s %s -> %s\n' "$key" "$(fingerprint "$from/$key")" "$(fingerprint "$to/$key")"
            fi
        fi
    done <<< "$keys"
    # 0 = identical, so `if render_diff ...` reads as "if there is nothing
    # to do". Non-zero means the caller must ask before touching anything.
    return "$changed"
}

confirm() {
    [ "$ASSUME_YES" -eq 1 ] && return 0
    printf 'apply this? [y/N] ' >&2
    read -r reply </dev/tty || return 1
    case "$reply" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# Secrets worth syncing: ours. Service-account tokens are minted by the
# cluster and Helm keeps its release state in secrets too; copying either
# would be noise at best and a restore that breaks things at worst.
list_cluster_secrets() {
    kubectl -n "$NS" get secrets \
        -o go-template='{{range .items}}{{if and (ne .type "kubernetes.io/service-account-token") (ne .type "helm.sh/release.v1")}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}'
}

sync_one() {
    local secret=$1 dir=$2 rc=0
    local work="$TMP/$secret"; rm -rf "$work"; mkdir -p "$work"

    case "$ACTION" in
    download)
        guard_gitignored "$dir"
        fetch_cluster_into "$secret" "$work/cluster"
        mkdir -p "$dir"
        echo "secret/$secret ($NS) -> $dir"
        if render_diff "$dir" "$work/cluster"; then
            echo "  no changes."
            return 0
        fi
        confirm || { echo "  skipped."; return 0; }
        rm -rf "${dir:?}"/*
        cp -a "$work/cluster"/. "$dir"/ 2>/dev/null || true
        chmod -R go-rwx "$dir"
        echo "  downloaded $(ls -1 "$dir" 2>/dev/null | wc -l | tr -d ' ') keys"
        ;;
    upload)
        [ -d "$dir" ] || { echo "no such directory: $dir" >&2; return 1; }
        guard_gitignored "$dir"
        fetch_cluster_into "$secret" "$work/cluster"
        echo "$dir -> secret/$secret ($NS)"
        if render_diff "$work/cluster" "$dir"; then
            echo "  no changes."
            return 0
        fi
        confirm || { echo "  skipped."; return 0; }
        local args=()
        for f in "$dir"/*; do
            [ -f "$f" ] || continue
            args+=(--from-file="$(basename "$f")=$f")
        done
        [ ${#args[@]} -gt 0 ] || { echo "  nothing to upload" >&2; return 1; }
        kubectl -n "$NS" create secret generic "$secret" "${args[@]}" \
            --dry-run=client -o yaml | kubectl -n "$NS" apply -f -
        ;;
    *)
        usage
        ;;
    esac
    return $rc
}

if [ -n "$SECRET" ]; then
    sync_one "$SECRET" "${DIR:-secrets/$SECRET}"
else
    # All of them. On download that is whatever the cluster holds; on
    # upload it is whatever we have locally, so a secret deleted from the
    # cluster is not silently recreated by a stale directory.
    if [ "$ACTION" = "download" ]; then
        names=$(list_cluster_secrets)
    else
        names=$(ls -1 "${DIR:-secrets}" 2>/dev/null || true)
    fi
    [ -n "$names" ] || { echo "nothing to sync." >&2; exit 0; }
    echo "$names" | while IFS= read -r name; do
        [ -n "$name" ] || continue
        sync_one "$name" "${DIR:-secrets}/$name"
        echo
    done
fi
