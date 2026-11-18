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

Writes one `.sql` per policy plus `00_combined_impact.sql`, an overview across
every Deny statement. Requires Python 3.8+, standard library only.

If your organization has more than a couple of hundred accounts, read
[Large organizations](#large-organizations) before anything else — the default
table shape does not scale that far, and the failure mode is a query that never
returns rather than one that returns the wrong thing.

## What it generates

Each Deny statement produces:

| Query | Purpose |
| --- | --- |
| **SUMMARY** | One row per account / principal / service / API / region with event counts. |
| **DETAIL** | The individual events behind a summary row, including `requestparameters`. |
| **RESOURCE INVENTORY** | Only for statements gated on `aws:ResourceTag/*` — see [Limits](#limits). |

And `00_combined_impact.sql` sits above them all, in one pass over the trail:

| Report | Purpose |
| --- | --- |
| **1. BLAST RADIUS** | One row per Deny statement: accounts affected, OUs affected, events, first/last seen. Start here. |
| **2. BY OU** | Only with `--accounts-table`. SCPs attach to OUs, so this is the row that decides whether attaching one is safe. |
| **3. BY ACCOUNT** | The loudest accounts per statement, truncated. Tells you where to look, not how much there is. |

The combined query evaluates every statement against a *single* scan rather
than `UNION ALL`-ing one `SELECT` per statement — Trino does not share a table
scan between UNION branches, so the old shape read the same bytes once per SCP.
Each statement's predicate becomes an `IF()` over the shared scan, and the array
of whichever ones matched is unnested, so an event two SCPs would both block
still contributes a row to each. Same answer, 1/N the bytes.

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

## Large organizations

An org trail's S3 layout is
`AWSLogs/<org>/<account>/CloudTrail/<region>/<yyyy>/<MM>/<dd>/`, so the Athena
table partitions on account × region × day. Partition projection resolves those
at query time by *listing every combination the filters do not rule out*, and
the generated queries only filter on the day:

```
   50 accounts × 34 regions × 123 days =     209,100 prefixes   fine
 2400 accounts × 34 regions × 123 days =  10,036,800 prefixes   never returns
```

It is not a slow query, it is a query that spends its 30-minute budget planning
and dies before reading a byte. Nothing you do to the SQL fixes it; the cost is
in the table.

**Pay that listing cost once instead.** `06_cloudtrail_compact.sql` is a Parquet
copy of the trail partitioned by date *alone*, with `account_id` and `region`
demoted to ordinary columns. The cross product disappears, every query sees all
accounts and all regions for free, and because the compacted table keeps the
same column names and struct shapes, every query the generator writes runs
against it unchanged — only `--partition-style` differs.

```
cd athena-ddl
./dump_org_accounts.sh > org_accounts.csv          # OU tree, for the join below
aws s3 cp org_accounts.csv s3://my-staging/lookups/org_accounts/

# add compact_location + accounts_location to the CSV row, then
./render_ddl.py trails.csv --force
./run_sql.py --work-group scp-impact rendered/prod-org/0[1368]*.sql
./run_sql.py --work-group scp-impact --jobs 8 rendered/prod-org/07_compact_backfill.sql
```

`07_compact_backfill.sql` is one `INSERT INTO` per day, and that is the whole
trick: pinning `timestamp` to a single day divides the listing by the length of
the window, so each statement probes accounts × regions × **1** and lands back
in normal Athena territory. `--jobs 8` runs them concurrently (Athena's default
DML concurrency quota is 20–25, so leave headroom). Its last statement
reconciles compacted against raw row counts, day by day.

`INSERT INTO` appends and is **not idempotent** — before retrying a failed day,
`aws s3 rm --recursive` its `dt=` prefix. `run_sql.py` stops at the first
failure and, with `--jobs > 1`, names every day in the batch that failed so you
know which prefixes to clear.

Keep the full region enum for the backfill. It is the one pass that has to see
everything, and after it the compacted table has `awsregion` as a plain column,
which dissolves the usual tension between narrowing the enum for speed and
keeping the regions an SCP is meant to deny.

Then point the generator at the compacted table — each rendered file carries the
matching invocation in its header:

```
./scp_to_athena.py --scp-dir scps \
    --database cloudtrail --table cloudtrail_logs_compact \
    --partition-style iso \
    --start 2026-07-01 --end 2026-10-31 \
    --accounts-table cloudtrail.org_accounts \
    --hits-table cloudtrail.scp_hits --hits-location s3://my-staging/scp_hits \
    --exclude-accounts <mgmt-account-id> \
    --out-dir athena-queries
```

Three things in there are specific to running at this size.

**`--accounts-table`** joins `08_org_accounts.sql`, which maps account IDs to
names and OU paths. SCPs attach to OUs, so "2400 accounts are affected" is not
an answer and "the Sandbox OU is affected" is; it adds the BY OU report. It also
replaces `--accounts`: scoping to an OU is a `LIKE` against `ou_path`, not 2400
IDs on a command line. `render_ddl.py` stops suggesting `--accounts` past 25
accounts for the same reason — the table already holds exactly those accounts,
so the `IN` list filters nothing.

**`--hits-table`/`--hits-location`** materialise the combined query's matched
events once, so its three reports read that small table instead of each
carrying its own scan. Takes `00_combined_impact.sql` from one scan per report
to one scan total. The location must be empty: `CREATE TABLE AS` refuses a
non-empty prefix and `DROP TABLE` does not clear it, so re-running the file
means `aws s3 rm --recursive` first. The file says so at the top.

**`--exclude-accounts <mgmt-account-id>`** — SCPs never apply to the management
account, and it is in the trail.

The per-SCP files are untouched by all this: they are still a SUMMARY and a
DETAIL scan each, which is fine because you open one at a time, after the
combined report has told you which one matters.

Costs that stay exact at this scale: event counts, and `accounts_affected` /
`ous_affected` in the combined query. Costs that switch to `approx_distinct`:
principals, APIs, regions, source IPs. An exact distinct count shuffles every
value to one node per group, and the groups here are already fine-grained;
that is a lot of shuffle to decide whether a number is 7 or 8.

## Table shape

Assumes the standard AWS CloudTrail Athena schema (`useridentity` struct,
`eventsource`, `eventname`, `resources` array, ...). If you do not already have
such a table, `athena-ddl/` has the DDL as templates:

| File | |
| --- | --- |
| `01_create_database.sql` | the `cloudtrail` Glue database |
| `02_cloudtrail_logs_projection.sql` | single-account trail, all regions, partition projection |
| `03_cloudtrail_logs_org_projection.sql` | **organization trail** — the one to use for SCP analysis |
| `04_cloudtrail_logs_ymd_manual.sql` | manual `year`/`month`/`day` partitions, for `--partition-style ymd` |
| `05_validate.sql` | smoke tests — run these before trusting the generated queries |
| `06_cloudtrail_compact.sql` | **Parquet copy partitioned by date alone** — see [Large organizations](#large-organizations) |
| `07_compact_backfill.sql` | the per-day `INSERT INTO`s that fill it, plus a reconcile |
| `08_org_accounts.sql` | account → OU lookup, for `--accounts-table` |
| `discover.sh` | read-only AWS calls that write the CSV for the renderer |
| `dump_org_accounts.sh` | read-only Organizations walk that writes `08`'s CSV |
| `render_ddl.py` | fills the templates in from that CSV |
| `run_sql.py` | runs a `.sql` file through Athena with the `aws` CLI |

Either fill in the `<BUCKET>` / `<ORG_ID>` / `<ACCOUNT_ID>` placeholders by hand
(each template lists its own in a `TEMPLATE-ONLY` block), or describe the trails
in a CSV and render them:

```
cd athena-ddl
./discover.sh --bucket-filter cloudtrail > trails.csv   # or --example-csv, and edit
./render_ddl.py trails.csv                              # -> rendered/<name>/*.sql
```

`discover.sh` builds the CSV from the account itself — `cloudtrail list-trails`
for the bucket/prefix/org flag, then the bucket layout for the org id, member
accounts, regions and earliest delivered day, so those columns describe what was
actually delivered rather than what is configured. It also picks up buckets whose
trail lives in another account (the usual org/log-archive split), which
`describe-trails` alone cannot see. Everything it finds that isn't a CSV column —
delivery errors, whether data events are logged, SSE-KMS, lifecycle expiry — comes
out as `#` comment lines that `render_ddl.py` skips. It is read-only; review the
CSV before rendering.

The `table` column comes out prefilled as `cloud_trail_<name>`, with anything
SQL cannot take in an identifier folded to `_` — the prefix also guarantees a
leading letter, which a bucket-derived name does not. `--table-prefix` changes
it. The two staging locations are flags rather than a hand edit per row:

```
./discover.sh --bucket-filter cloudtrail \
    --compact-location  s3://my-staging/compact \
    --accounts-location s3://my-staging/lookups > trails.csv
```

Both are filled into every row. One `--compact-location` serves all of them
because each trail's compacted table gets its own `<table>/` subprefix beneath
it; it must not overlap a trail bucket, and `render_ddl.py` warns if it does.
Without `--compact-location` the CSV carries a comment saying so, since that is
the column a large organization cannot do without.

One CSV row per trail; each row produces every variant its columns support —
`account_id` gets you the single-account table, `org_id` + `accounts` the org
table, adding `region` the ymd table, adding `compact_location` the compacted
table and its backfill — plus a `05_validate_<variant>.sql` whose partition
filters match that variant. `accounts_location` additionally renders the OU
lookup table. Past 200 accounts without a `compact_location` set, the renderer
warns with the prefix count the org table would make Athena list. The ymd variant's `ADD PARTITION`
statements are generated for the whole window and batched. Each rendered file
carries the `scp_to_athena.py` invocation that matches it, so the
`--database`/`--table`/`--partition-style` triple cannot drift from the table it
describes. `--only <variant>`, `--stdout` and `--force` are there too.

Partition projection needs no partition maintenance, but the account and region
enums must list everything you want searched: a region missing from the enum
returns no rows, which reads as "this SCP blocks nothing there." The default
enum is all 34 commercial regions (`./render_ddl.py --print-regions`); narrow it
with the CSV's `regions` column once you know which ones the org uses, since
Athena probes accounts × regions × days worth of prefixes.

Pick the partitioning with `--partition-style`:

| Value | Expects |
| --- | --- |
| `timestamp` (default) | a `timestamp` string column of `YYYY/MM/dd` — what the CloudTrail console's partition-projection table creates |
| `ymd` | separate `year` / `month` / `day` string columns |
| `date` | a single `DATE` column (`--partition-column` to rename) |
| `iso` | a `dt` string column of `YYYY-MM-DD` — the compacted table from `06` |
| `none` | no partition pruning — scans everything, so watch the cost |

`iso` is a string column rather than a `DATE` so the predicate is a plain string
`BETWEEN` with no cast, which cannot be tripped up by Athena's varchar/date
coercion rules.

An `eventtime` range predicate is always emitted as well, so the window is
correct even if the partition style is wrong; only the bytes scanned suffer.

## Running the SQL

`StartQueryExecution` takes one statement, and these files hold several — `04`
is a `CREATE` plus batched `ALTER`s, `05_validate_*` is five `SELECT`s, and each
generated query file is a SUMMARY plus a DETAIL. `run_sql.py` splits a file
(quote- and comment-aware, so a `;` in a string or comment does not end a
statement), submits each in order, waits, and prints state, bytes scanned and
the first rows:

```
cd athena-ddl
./run_sql.py --work-group scp-impact rendered/prod-org/*.sql
./run_sql.py --work-group scp-impact ../athena-queries/*.sql --save-results /tmp/out
./run_sql.py --work-group scp-impact --jobs 8 rendered/prod-org/07_compact_backfill.sql
./run_sql.py --dry-run rendered/prod-org/04_cloudtrail_logs_ymd_manual.sql
```

It stops at the first failure (`--continue-on-error` to override), since later
statements in a DDL file depend on the earlier ones.

`--jobs N` runs independent statements concurrently — a backfill is a hundred-odd
`INSERT`s that take minutes each and do not depend on each other, so serially it
is an afternoon. Only runs of consecutive statements with the *same*
parallel-safe keyword (`SELECT`/`WITH`/`INSERT`) go together; anything else is a
barrier that runs alone, in order. That is same-keyword rather than
same-safety because the mix is where the hazard is: the backfill's 101 `INSERT`s
are followed by a `SELECT` that counts what they wrote, and running it alongside
them would have it count a half-written table. A `CREATE`-then-`ALTER` DDL file
is unaffected by `--jobs` entirely. Either `--work-group` or
`--output-location s3://…` is required — Athena needs somewhere to write. A
workgroup is the better of the two because it can also cap the damage:

```
aws athena create-work-group --name scp-impact --configuration \
  'ResultConfiguration={OutputLocation=s3://my-athena-results/scp/},EnforceWorkGroupConfiguration=true,BytesScannedCutoffPerQuery=10737418240'
```

To run one statement by hand, note the `=` in `--query-string=file://…`: these
files open with a `--` comment line, and without it the CLI reads the value as
an option.

## Options

```
--scp-dir DIR              directory of SCP JSON files (or pass files/dirs positionally)
--database / --table       Glue database and CloudTrail table
--accounts-table DB.TABLE  account -> name/ou_path lookup; adds the BY OU report
--start / --end            YYYY-MM-DD, inclusive
--days N                   shorthand for the last N days
--accounts / --exclude-accounts
--status {non-denied,successful,all}
--include-service-principals
--partition-style {timestamp,ymd,date,iso,none} / --partition-column
--mode {both,summary,detail}
--limit N                  LIMIT on generated queries (default 500)
--service-map FILE         JSON of {iam_prefix: [eventsource, ...]} overrides
--no-combined              skip 00_combined_impact.sql
--hits-table DB.TABLE      materialise the combined query's matches, so its
--hits-location S3URI      reports read that instead of re-scanning the trail
--out-dir DIR / --stdout
```

## Tests

```
python3 -m unittest test_scp_to_athena
cd athena-ddl && python3 -m unittest test_render_ddl test_run_sql
```

64 tests covering glob translation, action/condition/resource mapping, NULL
safety, comment escaping, CLI scoping, and the combined query (one scan per
report rather than one per statement, exact vs. approximate counts, the OU
join); plus 76 for the DDL renderer (CSV validation, variant selection,
partition predicates and batching, placeholder exhaustion, and pinning the
backfill's positional `SELECT` list to `06`'s column order — `INSERT INTO`
binds by position, so drift there would shift data silently rather than
erroring); and 35 for the runner (statement splitting around quotes and
comments, and that `--jobs` never reorders or drops a statement). If `sqlglot`
is installed (`pip install sqlglot`) the generated SQL is also parse-checked
against the Athena dialect; those tests skip otherwise.
