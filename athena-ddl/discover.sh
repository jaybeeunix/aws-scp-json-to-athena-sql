#!/usr/bin/env bash
#
# discover.sh -- build a render_ddl.py CSV from what AWS actually reports.
#
#   ./discover.sh --bucket-filter cloudtrail > trails.csv
#   ./render_ddl.py trails.csv
#
# Two passes, in this order:
#
#   1. cloudtrail list-trails / describe-trails -- gives bucket, prefix and the
#      organization flag without guessing from names.
#   2. s3api list-buckets -- for buckets whose trail is defined in another
#      account, the normal case for an org trail landing in a log archive
#      account. Buckets already covered by pass 1 are skipped.
#
# Org id, member accounts, regions and the earliest day are read back out of the
# bucket layout, so they describe what was actually delivered rather than what is
# configured. Findings that are not CSV columns -- delivery errors, data event
# selectors, SSE-KMS, lifecycle expiry -- are emitted as `#` comment lines, which
# render_ddl.py skips.
#
# Read-only: every call is a List/Describe/Get. bash 3.2+, aws CLI v2, no jq.

set -euo pipefail

BUCKET_FILTER=""
MODE="both"          # both | trails | buckets
MAX_ACCOUNTS=50      # accounts to scan for the region union
DATE_SAMPLE=3        # accounts to drill for the earliest day
WITH_YMD=0

usage() {
    cat <<'EOF'
usage: discover.sh [options] > trails.csv

  --bucket-filter STR   only buckets whose name contains STR (default: all)
  --trails-only         skip the list-buckets pass
  --buckets-only        skip the cloudtrail pass
  --max-accounts N      accounts to scan when building the region union (default 50)
  --date-sample N       accounts to drill for the earliest day (default 3)
  --with-ymd            also fill the `region` column, which makes render_ddl.py
                        emit the manual year/month/day table as well
  --profile NAME        AWS profile
  --region NAME         default region for the API calls
  -h, --help

Progress and warnings go to stderr, the CSV to stdout.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --bucket-filter) BUCKET_FILTER="${2:?}"; shift 2 ;;
        --trails-only)   MODE="trails"; shift ;;
        --buckets-only)  MODE="buckets"; shift ;;
        --max-accounts)  MAX_ACCOUNTS="${2:?}"; shift 2 ;;
        --date-sample)   DATE_SAMPLE="${2:?}"; shift 2 ;;
        --with-ymd)      WITH_YMD=1; shift ;;
        --profile)       export AWS_PROFILE="${2:?}"; shift 2 ;;
        --region)        export AWS_DEFAULT_REGION="${2:?}"; shift 2 ;;
        -h|--help)       usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

warn()    { printf 'warning: %s\n' "$*" >&2; }
note()    { printf '%s\n' "$*" >&2; }
comment() { printf '# %s\n' "$*"; }

command -v aws >/dev/null 2>&1 || { echo "aws CLI not found" >&2; exit 1; }

SEEN_NAMES="$(mktemp)"
SEEN_BUCKETS="$(mktemp)"
trap 'rm -f "$SEEN_NAMES" "$SEEN_BUCKETS"' EXIT

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# Collapse `--output text` tabs to lines and drop JMESPath's literal "None".
untab() { tr '\t' '\n' | grep -v '^None$' | grep -v '^[[:space:]]*$' || true; }

# s3_children BUCKET PREFIX -- one child path segment per line.
s3_children() {
    local bucket="$1" prefix="$2" line
    aws s3api list-objects-v2 --bucket "$bucket" --prefix "$prefix" --delimiter / \
        --query 'CommonPrefixes[].Prefix' --output text 2>/dev/null | untab |
    while IFS= read -r line; do
        line="${line#"$prefix"}"
        line="${line%/}"
        if [ -n "$line" ]; then printf '%s\n' "$line"; fi
    done
}

first_child() { s3_children "$1" "$2" | sort | head -1; }

sanitize() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-' | sed 's/-*$//'; }

uniq_name() {
    local base name n=2
    base="$(sanitize "$1")"
    name="$base"
    while grep -qxF "$name" "$SEEN_NAMES" 2>/dev/null; do
        name="$base-$n"; n=$((n + 1))
    done
    printf '%s\n' "$name" >>"$SEEN_NAMES"
    printf '%s' "$name"
}

bucket_seen() { grep -qxF "$1" "$SEEN_BUCKETS" 2>/dev/null; }
mark_bucket() { printf '%s\n' "$1" >>"$SEEN_BUCKETS"; }

# Locate the AWSLogs/ segment: at the bucket root, or under one or two levels of
# key prefix. Echoes the prefix above it, empty when at the root. Returns 1 when
# the bucket holds no CloudTrail layout we recognise.
find_awslogs() {
    local bucket="$1" lvl1 lvl2
    if [ -n "$(s3_children "$bucket" "AWSLogs/")" ]; then
        return 0
    fi
    # fd 3/4 rather than stdin: the aws calls in the body would eat it.
    while IFS= read -r -u 3 lvl1; do
        [ -n "$lvl1" ] || continue
        if [ -n "$(s3_children "$bucket" "$lvl1/AWSLogs/")" ]; then
            printf '%s' "$lvl1"; return 0
        fi
        while IFS= read -r -u 4 lvl2; do
            [ -n "$lvl2" ] || continue
            if [ -n "$(s3_children "$bucket" "$lvl1/$lvl2/AWSLogs/")" ]; then
                printf '%s' "$lvl1/$lvl2"; return 0
            fi
        done 4< <(s3_children "$bucket" "$lvl1/" | head -20)
    done 3< <(s3_children "$bucket" "" | head -20)
    return 1
}

# earliest_day BUCKET BASE_PREFIX -- drills yyyy/MM/dd, echoes YYYY-MM-DD.
earliest_day() {
    local bucket="$1" base="$2" y m d
    y="$(first_child "$bucket" "$base")";       [ -n "$y" ] || return 0
    m="$(first_child "$bucket" "$base$y/")";    [ -n "$m" ] || return 0
    d="$(first_child "$bucket" "$base$y/$m/")"; [ -n "$d" ] || return 0
    printf '%s-%s-%s' "$y" "$m" "$d"
}

min_date() {
    if   [ -z "$1" ]; then printf '%s' "$2"
    elif [ -z "$2" ]; then printf '%s' "$1"
    elif [ "$1" \< "$2" ]; then printf '%s' "$1"
    else printf '%s' "$2"
    fi
}

# ---------------------------------------------------------------------------
# per-bucket inspection -- results land in these globals
# ---------------------------------------------------------------------------

I_ORG_ID=""; I_ACCOUNT_ID=""; I_ACCOUNTS=""; I_REGIONS=""; I_START=""; I_LAYOUT=""

inspect_bucket() {
    local bucket="$1" prefix="$2" root kids child accounts acct base r day
    local regions="" acct_regions="" n=0
    I_ORG_ID=""; I_ACCOUNT_ID=""; I_ACCOUNTS=""; I_REGIONS=""; I_START=""; I_LAYOUT=""

    root="AWSLogs/"
    [ -n "$prefix" ] && root="$prefix/AWSLogs/"

    kids="$(s3_children "$bucket" "$root")"
    if [ -z "$kids" ]; then
        warn "$bucket: nothing under $root (no access, or nothing delivered yet)"
        return 1
    fi

    # AWSLogs/o-xxxx/<account>/... for an org trail, AWSLogs/<account>/... otherwise.
    for child in $kids; do
        case "$child" in o-*) I_ORG_ID="$child"; break ;; esac
    done

    if [ -n "$I_ORG_ID" ]; then
        I_LAYOUT="org"
        accounts="$(s3_children "$bucket" "$root$I_ORG_ID/" | grep -E '^[0-9]{12}$' || true)"
    else
        I_LAYOUT="single"
        accounts="$(printf '%s\n' "$kids" | grep -E '^[0-9]{12}$' || true)"
        I_ACCOUNT_ID="$(printf '%s\n' "$accounts" | head -1)"
    fi
    if [ -z "$accounts" ]; then
        warn "$bucket: no account-id prefixes under $root$I_ORG_ID"
        return 1
    fi
    I_ACCOUNTS="$(printf '%s' "$accounts" | tr '\n' ' ' | sed 's/  *$//')"

    # Region union and earliest day, from the prefixes that actually exist.
    for acct in $accounts; do
        n=$((n + 1))
        if [ "$n" -gt "$MAX_ACCOUNTS" ]; then
            warn "$bucket: stopped after $MAX_ACCOUNTS accounts (--max-accounts); the regions column may be short"
            break
        fi
        if [ -n "$I_ORG_ID" ]; then base="$root$I_ORG_ID/$acct/CloudTrail/"
        else                        base="$root$acct/CloudTrail/"; fi
        acct_regions="$(s3_children "$bucket" "$base" | grep -E '^[a-z]{2}(-[a-z]+)+-[0-9]$' || true)"
        regions="$regions
$acct_regions"
        # Earliest day per region, not just the first one: a region added late
        # would otherwise hide an older region's data behind a newer start_date.
        if [ "$n" -le "$DATE_SAMPLE" ]; then
            for r in $acct_regions; do
                day="$(earliest_day "$bucket" "$base$r/")"
                I_START="$(min_date "$I_START" "$day")"
            done
        fi
    done
    I_REGIONS="$(printf '%s\n' "$regions" | grep -v '^[[:space:]]*$' | sort -u |
                 tr '\n' ' ' | sed 's/  *$//')"
    if [ -z "$I_REGIONS" ]; then
        # AWSLogs/<account>/ with no CloudTrail/<region>/ under it is some other
        # log type sharing the bucket (ELB, VPC flow logs), or nothing delivered.
        warn "$bucket: no CloudTrail/<region>/ prefixes under $root, skipping"
        return 1
    fi
    return 0
}

# Things worth knowing that are not CSV columns.
bucket_notes() {
    local bucket="$1" enc days
    enc="$(aws s3api get-bucket-encryption --bucket "$bucket" \
           --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
           --output text 2>/dev/null || true)"
    case "$enc" in
        aws:kms*) comment "$bucket is $enc encrypted -- the Athena query role needs kms:Decrypt on that key" ;;
    esac
    days="$(aws s3api get-bucket-lifecycle-configuration --bucket "$bucket" \
            --query 'Rules[?Status==`Enabled`].Expiration.Days' --output text 2>/dev/null |
            untab | sort -n | head -1 || true)"
    [ -n "$days" ] && comment "$bucket expires objects after $days days -- start_date cannot usefully predate that"
    return 0
}

trail_notes() {
    local arn="$1" region="$2" status logging err basic advanced
    status="$(aws cloudtrail get-trail-status --name "$arn" --region "$region" \
              --query '[IsLogging,LatestDeliveryError]' --output text 2>/dev/null || true)"
    if [ -n "$status" ]; then
        IFS=$'\t' read -r logging err <<EOF
$status
EOF
        [ "$logging" = "False" ] && comment "trail $arn is NOT logging -- recent days will be empty"
        [ -n "${err:-}" ] && [ "$err" != "None" ] && comment "trail $arn last delivery error: $err"
    fi
    basic="$(aws cloudtrail get-event-selectors --trail-name "$arn" --region "$region" \
             --query 'EventSelectors[].DataResources[].Type' --output text 2>/dev/null | untab || true)"
    advanced="$(aws cloudtrail get-event-selectors --trail-name "$arn" --region "$region" \
                --query 'AdvancedEventSelectors[].FieldSelectors[?Field==`resources.type`].Equals[]' \
                --output text 2>/dev/null | untab || true)"
    if [ -z "$basic" ] && [ -z "$advanced" ]; then
        comment "trail $arn logs management events only -- SCPs on data-plane actions (s3:GetObject, lambda:InvokeFunction) will look harmless here"
    else
        comment "trail $arn data events: $(printf '%s %s' "$basic" "$advanced" | tr '\n' ' ')"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# row emission
# ---------------------------------------------------------------------------

# emit_row NAME BUCKET PREFIX ACCOUNT_ID ORG_ID ACCOUNTS REGIONS START_DATE
emit_row() {
    local region=""
    if [ "$WITH_YMD" = "1" ]; then
        region="$(printf '%s' "$7" | awk '{print $1}')"
    fi
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,,,,\n' \
        "$1" "$2" "$3" "$4" "$5" "$6" "$region" "$7" "$8"
}

process_bucket() {
    local bucket="$1" prefix="$2" name_hint="$3" name acct
    bucket_seen "$bucket" && return 0
    mark_bucket "$bucket"

    if [ -z "$prefix" ]; then
        prefix="$(find_awslogs "$bucket" || true)"
        if [ -z "$prefix" ] && [ -z "$(s3_children "$bucket" "AWSLogs/")" ]; then
            warn "$bucket: no AWSLogs/ layout found, skipping"
            return 0
        fi
    fi

    note "inspecting s3://$bucket/${prefix:+$prefix/}AWSLogs/ ..."
    inspect_bucket "$bucket" "$prefix" || return 0

    name="$(uniq_name "${name_hint:-$bucket}")"
    acct="$I_ACCOUNT_ID"
    # The org table keys on the account_id prefixes, not on one owning account.
    [ "$I_LAYOUT" = "org" ] && acct=""

    comment "s3://$bucket/${prefix:+$prefix/}AWSLogs/ -- $I_LAYOUT layout${I_ORG_ID:+ ($I_ORG_ID)}"
    bucket_notes "$bucket"
    emit_row "$name" "$bucket" "$prefix" "$acct" "$I_ORG_ID" "$I_ACCOUNTS" \
             "$I_REGIONS" "$I_START"
}

# ---------------------------------------------------------------------------
# passes
# ---------------------------------------------------------------------------

pass_trails() {
    local listed arn home row tname bucket prefix
    listed="$(aws cloudtrail list-trails --query 'Trails[].[TrailARN,HomeRegion]' \
              --output text 2>/dev/null | sort -u || true)"
    if [ -z "$listed" ]; then
        note "no trails visible from this account -- relying on the bucket pass"
        return 0
    fi
    # No pipe into the loop: process_bucket updates state a subshell would drop.
    # fd 3 rather than stdin, which the aws calls in the body would consume.
    while IFS=$'\t' read -r -u 3 arn home; do
        [ -n "${arn:-}" ] || continue
        row="$(aws cloudtrail describe-trails --trail-name-list "$arn" --region "$home" \
               --query 'trailList[0].[Name,S3BucketName,S3KeyPrefix]' \
               --output text 2>/dev/null || true)"
        if [ -z "$row" ]; then warn "cannot describe $arn"; continue; fi
        IFS=$'\t' read -r tname bucket prefix <<EOF
$row
EOF
        [ "${prefix:-None}" = "None" ] && prefix=""
        [ -n "${bucket:-}" ] && [ "$bucket" != "None" ] || continue
        if [ -n "$BUCKET_FILTER" ]; then
            case "$bucket" in *"$BUCKET_FILTER"*) ;; *) continue ;; esac
        fi
        bucket_seen "$bucket" && continue
        trail_notes "$arn" "$home"
        process_bucket "$bucket" "$prefix" "$tname"
    done 3<<EOF
$listed
EOF
}

pass_buckets() {
    local buckets bucket
    buckets="$(aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | untab || true)"
    if [ -z "$buckets" ]; then
        warn "cannot list buckets in this account"
        return 0
    fi
    while IFS= read -r -u 3 bucket; do
        [ -n "$bucket" ] || continue
        if [ -n "$BUCKET_FILTER" ]; then
            case "$bucket" in *"$BUCKET_FILTER"*) ;; *) continue ;; esac
        fi
        process_bucket "$bucket" "" ""
    done 3<<EOF
$buckets
EOF
}

# ---------------------------------------------------------------------------

caller="$(aws sts get-caller-identity --query '[Account,Arn]' --output text 2>/dev/null | tr '\t' ' ' || true)"
[ -n "$caller" ] || { echo "cannot call sts:GetCallerIdentity -- are credentials set?" >&2; exit 1; }
note "caller: $caller"

echo "name,bucket,prefix,account_id,org_id,accounts,region,regions,start_date,end_date,database,table,styles"
comment "generated by discover.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ) as $caller"
comment "accounts/regions/start_date are read back from the bucket -- what was delivered, not what is configured"

if [ "$MODE" != "buckets" ]; then pass_trails; fi
if [ "$MODE" != "trails" ];  then pass_buckets; fi

comment "SCPs never apply to the management account -- drop it from accounts, or pass --exclude-accounts to scp_to_athena.py"
note "done -- review the CSV, then: ./render_ddl.py trails.csv"
