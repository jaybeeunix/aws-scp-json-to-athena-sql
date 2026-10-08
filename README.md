# scp-to-athena

Converts AWS Service Control Policy JSON into Athena SQL that searches CloudTrail
S3 logs for activity the SCP **would have blocked**.

Use it to answer "what breaks if I attach this SCP?" before you attach it.

```
./scp_to_athena.py --scp-dir scps \
    --database cloudtrail --table cloudtrail_logs \
    --start 2025-06-01 --end 2025-09-09 \
    --out-dir athena-queries
```

Writes one `.sql` per policy plus `00_combined_impact.sql`, a UNION ALL overview
across every Deny statement. Requires Python 3.8+, standard library only.

## What it generates

Each Deny statement produces:

| Query | Purpose |
| --- | --- |
| **SUMMARY** | One row per account / principal / service / API / region with event counts. Start here. |
| **DETAIL** | The individual events behind a summary row, including `requestparameters`. |
| **RESOURCE INVENTORY** | Only for statements gated on `aws:ResourceTag/*` — see [Limits](#limits). |

Every file opens with a header recording the source policy, the statement it came
from, and a `CAVEATS` block listing anything the translation could not do
faithfully. **Read that block before acting on the numbers.**

## How statements are translated

| SCP element | CloudTrail |
| --- | --- |
| `Action: "svc:Api"` | `eventsource = 'svc.amazonaws.com' AND eventname = 'Api'` |
| `Action: "svc:*"` | `eventsource = 'svc.amazonaws.com'` |
| `Action: "svc:Put*"` | `eventname LIKE 'Put%'` |
| `NotAction` | `NOT (<union of the listed actions>)` |
| `Resource` | `resources[].arn` regex match, OR a substring match on `requestparameters` |
| `NotResource` | negated form of the above |
| `Condition` | one `AND` conjunct per condition key |

Condition keys that map cleanly:

`aws:RequestedRegion`, `aws:PrincipalArn`, `aws:PrincipalAccount`,
`aws:PrincipalType`, `aws:userid`, `aws:username`, `aws:SourceIp`,
`aws:SourceVpce`, `aws:UserAgent`, `aws:MultiFactorAuthPresent`,
`aws:ViaAWSService`, `aws:PrincipalIsAWSService`, `aws:CalledVia`,
`aws:SecureTransport`.

`aws:RequestTag/*` and `aws:TagKeys` are approximated by regex over the raw
`requestparameters` JSON, because tag shapes differ per service
(`{"key":..}` for EC2, `{"Key":..}` for RDS, and so on). Expect both false
positives and false negatives from those, and spot-check the hits.

Some details the generator gets right that a hand-written query usually doesn't:

- **`aws:PrincipalArn` is the *role* ARN, not the session ARN.** For an assumed
  role, that lives in `useridentity.sessioncontext.sessionissuer.arn`;
  `useridentity.arn` holds the `assumed-role/.../session` form and will not match
  an `arn:aws:iam::*:role/...` pattern. The generated SQL coalesces the two.
- **Negated conditions are NULL-safe.** `NOT (NULL LIKE '...')` is `NULL`, not
  `TRUE`, so an un-guarded `ArnNotLike` silently drops exactly the rows it should
  catch. Every string comparison is wrapped in `COALESCE(..., '')`.
- **IAM prefixes are not always the eventsource.** `cloudwatch:*` is logged under
  `monitoring.amazonaws.com`, `stepfunctions:*` under `states.amazonaws.com`,
  `emr:*` under `elasticmapreduce.amazonaws.com`, `docdb`/`neptune` under
  `rds.amazonaws.com`, and so on. See `SERVICE_EVENTSOURCE_OVERRIDES` in the
  script; extend it with `--service-map overrides.json`
  (`{"myservice": ["myservice-api.amazonaws.com"]}`).
- **Rows an SCP could never have blocked are excluded** — AWS service principals,
  service-linked roles (`:role/aws-service-role/`), and `AwsServiceEvent`
  records. Pass `--include-service-principals` to keep them. SCPs also do not
  apply to the management account: exclude it with
  `--exclude-accounts <mgmt-account-id>`.
- **Calls that were already denied are dropped** by default, so the output is
  access that actually succeeded or failed for some other reason. Change with
  `--status successful` (only `errorcode IS NULL`) or `--status all`.

## Limits

The generator is deliberately loud about what it cannot do. Anywhere a condition
cannot be evaluated it emits `TRUE /* unevaluable */` and records a caveat, so
the query **over-matches** rather than quietly under-matching. Treat those
results as candidates to review, not confirmed breakage.

- **`aws:ResourceTag/*` is not in CloudTrail.** The log records the API call, not
  the tags on the target resource. Those statements get a third RESOURCE
  INVENTORY query listing the distinct resource ARNs touched; cross-reference
  those against AWS Config or the Resource Groups Tagging API to find which ones
  actually carry the tag. Also unavailable: `aws:PrincipalTag/*`,
  `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, `aws:SourceArn`,
  `aws:SourceAccount`.
- **`eventname` is not always the IAM action.** `s3:ListBucket` is logged as
  `ListObjects`/`ListObjectsV2`, for instance. Named-action predicates can
  under-match; service-wide (`svc:*`) predicates are unaffected.
- **Data events must be enabled to appear at all.** S3 object-level, DynamoDB
  item-level, Lambda invoke, SNS publish and SQS message calls are data events.
  If the trail only logs management events, an SCP denying `s3:GetObject` will
  look harmless here.
- **`Resource` matching is best-effort.** `resources[]` is reliably populated for
  data events but frequently empty for management events, so the query also does
  a substring search of `requestparameters`. That can produce false positives.
- **Allow statements are skipped.** They widen permissions and block nothing on
  their own, so there is nothing to search for.
- **This is a log search, not a policy simulator.** It does not evaluate RCPs,
  permission boundaries, identity policies, or resource policies, and it cannot
  see calls that were never made. Absence of rows is weak evidence.
- Placeholder-looking values (`your-organization-...`, `…`, `example`) are
  flagged in the caveats — `RHCloudGovnPreventCloudTrailS3BucketDeletion` and
  `RHCloudGovnDenyCreationWithoutMandatoryTags` in `scps/` both still contain
  them and will not match anything real until filled in.

## Table shape

Assumes the standard AWS CloudTrail Athena schema (`useridentity` struct,
`eventsource`, `eventname`, `resources` array, ...). If you do not already have
such a table, `athena-ddl/` has the DDL:

| File | |
| --- | --- |
| `01_create_database.sql` | the `cloudtrail` Glue database |
| `02_cloudtrail_logs_projection.sql` | single-account trail, all regions, partition projection |
| `03_cloudtrail_logs_org_projection.sql` | **organization trail** — the one to use for SCP analysis |
| `04_cloudtrail_logs_ymd_manual.sql` | manual `year`/`month`/`day` partitions, for `--partition-style ymd` |
| `05_validate.sql` | smoke tests — run these before trusting the generated queries |

Fill in the `<BUCKET>` / `<ORG_ID>` / account-list placeholders first. Partition
projection needs no partition maintenance, but the account and region enums must
list everything you want searched: a region missing from the enum returns no
rows, which reads as "this SCP blocks nothing there."

Pick the partitioning with `--partition-style`:

| Value | Expects |
| --- | --- |
| `timestamp` (default) | a `timestamp` string column of `YYYY/MM/dd` — what the CloudTrail console's partition-projection table creates |
| `ymd` | separate `year` / `month` / `day` string columns |
| `date` | a single `DATE` column (`--partition-column` to rename) |
| `none` | no partition pruning — scans everything, so watch the cost |

An `eventtime` range predicate is always emitted as well, so the window is
correct even if the partition style is wrong; only the bytes scanned suffer.

## Options

```
--scp-dir DIR              directory of SCP JSON files (or pass files/dirs positionally)
--database / --table       Glue database and CloudTrail table
--start / --end            YYYY-MM-DD, inclusive
--days N                   shorthand for the last N days
--accounts / --exclude-accounts
--status {non-denied,successful,all}
--include-service-principals
--partition-style / --partition-column
--mode {both,summary,detail}
--limit N                  LIMIT on generated queries (default 500)
--service-map FILE         JSON of {iam_prefix: [eventsource, ...]} overrides
--no-combined              skip 00_combined_impact.sql
--out-dir DIR / --stdout
```

## Tests

```
python3 -m unittest test_scp_to_athena
```

48 tests covering glob translation, action/condition/resource mapping, NULL
safety, comment escaping, and CLI scoping. If `sqlglot` is installed
(`pip install sqlglot`) the generated SQL is also parse-checked against the
Athena dialect; those tests skip otherwise.
