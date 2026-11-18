#!/usr/bin/env bash
#
# dump_org_accounts.sh -- CSV of every account in the organization and its OU path.
#
#   ./dump_org_accounts.sh > org_accounts.csv
#   aws s3 cp org_accounts.csv s3://my-bucket/athena/org_accounts/org_accounts.csv
#
# Feeds 08_org_accounts.sql. SCPs attach to OUs, so this is what turns "2400 accounts
# are affected" into "the Sandbox OU is affected" -- see that file for why the join
# matters more the bigger the org is.
#
# Walks the OU tree top-down with list-organizational-units-for-parent and
# list-accounts-for-parent, which costs one call per OU and gives each account's full
# path for free. The obvious alternative -- list-accounts, then list-parents per account
# -- is one call per ACCOUNT plus one per ancestor, so about 10x the calls at 2400
# members, and Organizations throttles hard.
#
# Run it in the management account or a delegated administrator for Organizations.
# Read-only: List/Describe only. bash 3.2+, aws CLI v2, no jq.

set -euo pipefail

MAX_DEPTH=5          # Organizations allows 5 levels of OU nesting below the root
SEPARATOR="/"

usage() {
    cat <<'EOF'
usage: dump_org_accounts.sh [options] > org_accounts.csv

  --max-depth N     OU nesting levels to walk (default 5, the Organizations maximum)
  --separator STR   ou_path separator (default /)
  --profile NAME    AWS profile
  --region NAME     region for the API calls
  -h, --help

Progress goes to stderr, CSV to stdout. Columns match 08_org_accounts.sql:
account_id, account_name, account_email, account_status, ou_id, ou_name, ou_path
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --max-depth) MAX_DEPTH="${2:?}"; shift 2 ;;
        --separator) SEPARATOR="${2:?}"; shift 2 ;;
        --profile)   export AWS_PROFILE="${2:?}"; shift 2 ;;
        --region)    export AWS_DEFAULT_REGION="${2:?}"; shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

note() { printf '%s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }

command -v aws >/dev/null 2>&1 || { echo "aws CLI not found" >&2; exit 1; }

# RFC 4180: double any embedded quote, and quote every field. Account names and
# especially emails routinely contain commas, and OpenCSVSerde does respect quoting.
csv_field() {
    printf '"%s"' "$(printf '%s' "$1" | sed 's/"/""/g')"
}

csv_row() {
    local out="" field
    for field in "$@"; do
        [ -n "$out" ] && out="$out,"
        out="$out$(csv_field "$field")"
    done
    printf '%s\n' "$out"
}

ACCOUNTS_SEEN=0

# emit_accounts <parent-id> <ou-id> <ou-name> <ou-path>
emit_accounts() {
    local parent="$1" ou_id="$2" ou_name="$3" ou_path="$4"
    local line id name email status
    # --output text with an explicit query keeps the column order stable; tabs
    # separate, so a comma in a name cannot break the parse the way --output text
    # on a whole object can.
    while IFS=$'\t' read -r id name email status; do
        [ -n "$id" ] || continue
        csv_row "$id" "$name" "$email" "$status" "$ou_id" "$ou_name" "$ou_path"
        ACCOUNTS_SEEN=$((ACCOUNTS_SEEN + 1))
    done < <(aws organizations list-accounts-for-parent \
                 --parent-id "$parent" \
                 --query 'Accounts[].[Id,Name,Email,Status]' \
                 --output text 2>/dev/null || true)
}

# walk <parent-id> <ou-id> <ou-name> <path> <depth>
walk() {
    local parent="$1" ou_id="$2" ou_name="$3" path="$4" depth="$5"
    emit_accounts "$parent" "$ou_id" "$ou_name" "$path"

    if [ "$depth" -ge "$MAX_DEPTH" ]; then
        warn "stopping at depth $depth under $path; raise --max-depth if the tree is deeper"
        return
    fi

    local child_id child_name
    while IFS=$'\t' read -r child_id child_name; do
        [ -n "$child_id" ] || continue
        walk "$child_id" "$child_id" "$child_name" "$path$SEPARATOR$child_name" \
             $((depth + 1))
    done < <(aws organizations list-organizational-units-for-parent \
                 --parent-id "$parent" \
                 --query 'OrganizationalUnits[].[Id,Name]' \
                 --output text 2>/dev/null || true)
}

ROOT_ID="$(aws organizations list-roots --query 'Roots[0].Id' --output text)"
if [ -z "$ROOT_ID" ] || [ "$ROOT_ID" = "None" ]; then
    echo "could not read the organization root -- run this in the management account" \
         "or an Organizations delegated administrator" >&2
    exit 1
fi
ORG_ID="$(aws organizations describe-organization \
              --query 'Organization.Id' --output text 2>/dev/null || echo unknown)"
note "organization $ORG_ID, root $ROOT_ID"

# Header first: 08_org_accounts.sql sets skip.header.line.count=1.
csv_row account_id account_name account_email account_status ou_id ou_name ou_path
walk "$ROOT_ID" "$ROOT_ID" "Root" "Root" 0

note "$ACCOUNTS_SEEN account(s) written"

# A member count that disagrees with list-accounts means the walk missed a subtree --
# almost always --max-depth, occasionally an OU the caller cannot list.
TOTAL="$(aws organizations list-accounts --query 'length(Accounts)' --output text \
             2>/dev/null || echo "")"
if [ -n "$TOTAL" ] && [ "$TOTAL" != "None" ] && [ "$TOTAL" != "$ACCOUNTS_SEEN" ]; then
    warn "list-accounts reports $TOTAL accounts but the OU walk found $ACCOUNTS_SEEN;" \
         "the difference is accounts in OUs this walk did not reach"
fi
