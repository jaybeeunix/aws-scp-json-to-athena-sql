#!/usr/bin/env python3
"""
render_ddl.py -- fill in the CloudTrail Athena DDL templates from a CSV.

One CSV row describes one trail. For each row the script writes a ready-to-run
copy of every DDL variant that row has the variables for:

  projection  02_cloudtrail_logs_projection.sql      single-account trail
  org         03_cloudtrail_logs_org_projection.sql  organization trail
  ymd         04_cloudtrail_logs_ymd_manual.sql      manual year/month/day partitions

plus 01_create_database.sql once per row, and a 05_validate_<variant>.sql whose
partition filters match that variant's partitioning. The ymd variant also gets
its ALTER TABLE ... ADD PARTITION statements generated for the whole window,
batched so the console can run them.

Usage
-----
  ./render_ddl.py trails.csv --out-dir rendered
  ./render_ddl.py trails.csv --only org --stdout
  ./render_ddl.py --example-csv > trails.csv
  ./render_ddl.py --print-regions

CSV columns (header row required, order does not matter, blank cells take the
default, rows starting with # are ignored)
-----------------------------------------------------------------------------
  name        required  output subdirectory; [A-Za-z0-9._-]
  bucket      required  S3 bucket holding the trail
  start_date  required  first day of data; also the analysis window start
  prefix                key prefix under the bucket, above AWSLogs/
  end_date              default NOW (projection range) / today (ymd partitions)
  database              default cloudtrail
  table                 default cloudtrail_logs; _org / _ymd appended per variant
  account_id            12 digits -- enables `projection` and `ymd`
  org_id                o-xxxxxxxxxx -- enables `org`
  accounts              member accounts for the org enum (comma/space/; separated)
  region                one region -- required by `ymd`, which is single-region
  regions               region enum override; default is all 34 commercial regions
  styles                subset of projection/org/ymd; default is every eligible one
  table_projection / table_org / table_ymd
                        per-variant table name, overriding `table` + suffix

Python 3.8+, standard library only.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import re
import sys
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))

# Every region in the `aws` (commercial) partition. GovCloud, China and the iso
# partitions are deliberately absent -- each is a separate partition with its own
# trail bucket, so listing them here would only add prefixes that never exist.
# Override per trail with the CSV's `regions` column.
ALL_REGIONS: Tuple[str, ...] = (
    "af-south-1", "ap-east-1", "ap-east-2", "ap-northeast-1", "ap-northeast-2",
    "ap-northeast-3", "ap-south-1", "ap-south-2", "ap-southeast-1",
    "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-southeast-5",
    "ap-southeast-6", "ap-southeast-7", "ca-central-1", "ca-west-1",
    "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "il-central-1", "me-central-1",
    "me-south-1", "mx-central-1", "sa-east-1", "us-east-1", "us-east-2",
    "us-west-1", "us-west-2",
)

DB_TEMPLATE = "01_create_database.sql"
VALIDATE_TEMPLATE = "05_validate.sql"

# variant -> (template file, default table suffix, --partition-style to pass to
#             scp_to_athena.py, CSV columns the variant cannot be built without)
VARIANTS: Dict[str, Tuple[str, str, str, Tuple[str, ...]]] = {
    "projection": ("02_cloudtrail_logs_projection.sql", "", "timestamp",
                   ("account_id",)),
    "org": ("03_cloudtrail_logs_org_projection.sql", "_org", "timestamp",
            ("org_id", "accounts")),
    "ymd": ("04_cloudtrail_logs_ymd_manual.sql", "_ymd", "ymd",
            ("account_id", "region")),
}
VARIANT_ORDER = ("projection", "org", "ymd")

KNOWN_PLACEHOLDERS = (
    "<DATABASE>", "<TABLE>", "<BUCKET>", "<PREFIX>", "<ACCOUNT_ID>", "<ORG_ID>",
    "<REGION>", "<REGIONS>", "<ACCOUNT_IDS>", "<RANGE_START>", "<RANGE_END>",
    "<ADD_PARTITIONS>", "<SAMPLE_DAY_PREDICATE>", "<WINDOW_PREDICATE>",
    "<WINDOW_START>", "<WINDOW_END>",
)
# `<TOKENS>` is prose in the template headers, not a value to substitute.
PLACEHOLDER_RE = re.compile(r"<[A-Z][A-Z0-9_]*>")
PROSE_PLACEHOLDERS = {"<TOKENS>"}
# Instructions for filling a template in by hand. Useful in the template, noise
# once it is rendered, so the renderer drops these blocks.
TEMPLATE_ONLY_RE = re.compile(
    r"^-- TEMPLATE-ONLY BEGIN\n.*?^-- TEMPLATE-ONLY END\n", re.M | re.S)

COLUMNS = (
    "name", "bucket", "prefix", "database", "table", "account_id", "org_id",
    "accounts", "region", "regions", "start_date", "end_date", "styles",
    "table_projection", "table_org", "table_ymd",
)

NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ACCOUNT_RE = re.compile(r"^\d{12}$")
ORG_RE = re.compile(r"^o-[a-z0-9]{10,32}$")
REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")

# Athena caps query length; batching keeps each ALTER well under it and keeps the
# console usable.
PARTITIONS_PER_STATEMENT = 100
# A window this long is almost certainly a typo in start_date.
LONG_WINDOW_DAYS = 1000


class CsvError(Exception):
    """A problem with the input CSV, reported with the offending line number."""


# ---------------------------------------------------------------------------
# parsing / validation
# ---------------------------------------------------------------------------

def split_list(value: str) -> List[str]:
    """Split a multi-value cell on commas, semicolons or whitespace, de-duped."""
    parts = [p for p in re.split(r"[,;\s]+", value.strip()) if p]
    seen: Dict[str, None] = {}
    for p in parts:
        seen.setdefault(p, None)
    return list(seen)


def parse_date(value: str, field: str, lineno: int) -> dt.date:
    for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
        try:
            return dt.datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    raise CsvError("line %d: %s=%r is not a date (use YYYY-MM-DD)"
                   % (lineno, field, value))


class Trail:
    """One CSV row, validated."""

    def __init__(self, row: Dict[str, str], lineno: int, today: dt.date) -> None:
        self.lineno = lineno
        get = lambda key: (row.get(key) or "").strip()  # noqa: E731

        self.name = get("name")
        if not self.name:
            raise CsvError("line %d: name is required" % lineno)
        if not NAME_RE.match(self.name):
            raise CsvError("line %d: name=%r must match [A-Za-z0-9._-]"
                           % (lineno, self.name))

        self.bucket = get("bucket")
        if not self.bucket:
            raise CsvError("line %d: bucket is required" % lineno)
        if not BUCKET_RE.match(self.bucket):
            raise CsvError("line %d: bucket=%r is not a valid S3 bucket name"
                           % (lineno, self.bucket))

        self.prefix = get("prefix").strip("/")
        self.database = get("database") or "cloudtrail"
        self.table = get("table") or "cloudtrail_logs"
        for field, value in (("database", self.database), ("table", self.table)):
            if not IDENT_RE.match(value):
                raise CsvError("line %d: %s=%r is not a bare SQL identifier"
                               % (lineno, field, value))

        self.account_id = get("account_id")
        if self.account_id and not ACCOUNT_RE.match(self.account_id):
            raise CsvError("line %d: account_id=%r must be 12 digits"
                           % (lineno, self.account_id))

        self.org_id = get("org_id")
        if self.org_id and not ORG_RE.match(self.org_id):
            raise CsvError("line %d: org_id=%r must look like o-abc1234567"
                           % (lineno, self.org_id))

        self.accounts = split_list(get("accounts"))
        for acct in self.accounts:
            if not ACCOUNT_RE.match(acct):
                raise CsvError("line %d: accounts entry %r must be 12 digits"
                               % (lineno, acct))

        self.region = get("region")
        if self.region and not REGION_RE.match(self.region):
            raise CsvError("line %d: region=%r does not look like a region"
                           % (lineno, self.region))

        self.regions = split_list(get("regions")) or list(ALL_REGIONS)
        for region in self.regions:
            if not REGION_RE.match(region):
                raise CsvError("line %d: regions entry %r does not look like a region"
                               % (lineno, region))

        if not get("start_date"):
            raise CsvError("line %d: start_date is required -- it bounds the "
                           "projection range and the partitions to register" % lineno)
        self.start = parse_date(get("start_date"), "start_date", lineno)
        end_raw = get("end_date")
        self.end: Optional[dt.date] = (
            parse_date(end_raw, "end_date", lineno) if end_raw else None)
        if self.end and self.end < self.start:
            raise CsvError("line %d: end_date %s is before start_date %s"
                           % (lineno, self.end, self.start))
        # Concrete end for partition generation and for the sample day; `end`
        # staying None is what turns the projection range into ",NOW".
        self.end_concrete = self.end or today

        self.table_overrides = {
            v: get("table_" + v) for v in VARIANT_ORDER if get("table_" + v)}
        for variant, value in self.table_overrides.items():
            if not IDENT_RE.match(value):
                raise CsvError("line %d: table_%s=%r is not a bare SQL identifier"
                               % (lineno, variant, value))

        requested = [s.lower() for s in split_list(get("styles"))]
        if requested in ([], ["all"]):
            self.requested_styles: Optional[List[str]] = None
        else:
            unknown = [s for s in requested if s not in VARIANTS]
            if unknown:
                raise CsvError("line %d: styles=%s -- unknown style(s) %s; pick from %s"
                               % (lineno, get("styles"), ", ".join(unknown),
                                  ", ".join(VARIANT_ORDER)))
            self.requested_styles = [v for v in VARIANT_ORDER if v in requested]

    # -- derived ----------------------------------------------------------

    def has(self, column: str) -> bool:
        return bool(getattr(self, column))

    def missing_for(self, variant: str) -> List[str]:
        return [c for c in VARIANTS[variant][3] if not self.has(c)]

    def variants(self) -> List[str]:
        """Which variants to render, and why a requested one cannot be."""
        if self.requested_styles is None:
            return [v for v in VARIANT_ORDER if not self.missing_for(v)]
        for variant in self.requested_styles:
            missing = self.missing_for(variant)
            if missing:
                raise CsvError(
                    "line %d: styles asks for %r but %s %s not set"
                    % (self.lineno, variant, ", ".join(missing),
                       "is" if len(missing) == 1 else "are"))
        return list(self.requested_styles)

    def table_for(self, variant: str) -> str:
        if variant in self.table_overrides:
            return self.table_overrides[variant]
        return self.table + VARIANTS[variant][1]

    def warnings(self) -> List[str]:
        out = []
        for region in self.regions:
            if region.startswith("us-gov-"):
                out.append("regions includes %s: GovCloud is a separate partition "
                           "and never appears in a commercial trail bucket" % region)
            elif region not in ALL_REGIONS:
                out.append("regions includes %s, which is not a known commercial "
                           "region -- fine if it launched recently, a typo otherwise"
                           % region)
        if self.region and self.region not in self.regions:
            out.append("region=%s is not in the regions enum; the ymd table is "
                       "unaffected but the projection tables will not see it"
                       % self.region)
        if self.org_id and self.account_id and self.account_id in self.accounts:
            out.append("account_id %s is also in accounts; if that is the "
                       "management account, SCPs never apply to it -- pass "
                       "--exclude-accounts to scp_to_athena.py" % self.account_id)
        days = (self.end_concrete - self.start).days + 1
        if days > LONG_WINDOW_DAYS:
            out.append("window is %d days (%s..%s); the ymd variant would register "
                       "that many partitions" % (days, self.start, self.end_concrete))
        return out


def read_trails(path: str, today: dt.date) -> List[Trail]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            raise CsvError("%s: no header row" % path)
        fieldnames = [(f or "").strip().lower() for f in reader.fieldnames]
        unknown = [f for f in fieldnames if f and f not in COLUMNS]
        if unknown:
            raise CsvError("%s: unknown column(s) %s; known columns are %s"
                           % (path, ", ".join(unknown), ", ".join(COLUMNS)))

        trails: List[Trail] = []
        errors: List[str] = []
        seen: Dict[str, int] = {}
        for raw in reader:
            lineno = reader.line_num
            row = {(k or "").strip().lower(): (v or "")
                   for k, v in raw.items() if k is not None}
            if not any(v.strip() for v in row.values()):
                continue
            if (row.get("name") or "").strip().startswith("#"):
                continue
            try:
                trail = Trail(row, lineno, today)
                if trail.name in seen:
                    raise CsvError("line %d: duplicate name %r (also on line %d)"
                                   % (lineno, trail.name, seen[trail.name]))
                seen[trail.name] = lineno
                trail.variants()  # surface an impossible `styles` request now
                trails.append(trail)
            except CsvError as exc:
                errors.append(str(exc))

        if errors:
            raise CsvError("\n".join(errors))
        if not trails:
            raise CsvError("%s: no data rows" % path)
        return trails


# ---------------------------------------------------------------------------
# SQL fragments
# ---------------------------------------------------------------------------

def s3_url(bucket: str, *parts: str, trailing_slash: bool = False) -> str:
    segments = [p.strip("/") for p in parts if p and p.strip("/")]
    url = "s3://" + bucket.strip("/")
    if segments:
        url += "/" + "/".join(segments)
    return url + "/" if trailing_slash else url


def daterange(start: dt.date, end: dt.date) -> Iterable[dt.date]:
    day = start
    step = dt.timedelta(days=1)
    while day <= end:
        yield day
        day += step


def day_predicate(style: str, day: dt.date) -> str:
    if style == "ymd":
        return ("\"year\" = '%04d' AND \"month\" = '%02d' AND \"day\" = '%02d'"
                % (day.year, day.month, day.day))
    return "\"timestamp\" = '%s'" % day.strftime("%Y/%m/%d")


def window_predicate(style: str, start: dt.date, end: dt.date) -> str:
    lo, hi = start.strftime("%Y/%m/%d"), end.strftime("%Y/%m/%d")
    if style == "ymd":
        # Same shape scp_to_athena.py emits for --partition-style ymd.
        return ("concat(\"year\", '/', lpad(\"month\", 2, '0'), '/', "
                "lpad(\"day\", 2, '0'))\n      BETWEEN '%s' AND '%s'" % (lo, hi))
    return "\"timestamp\" BETWEEN '%s' AND '%s'" % (lo, hi)


def add_partitions_sql(table_fqn: str, bucket: str, prefix: str, account_id: str,
                       region: str, start: dt.date, end: dt.date) -> str:
    days = list(daterange(start, end))
    statements = []
    for i in range(0, len(days), PARTITIONS_PER_STATEMENT):
        batch = days[i:i + PARTITIONS_PER_STATEMENT]
        lines = ["ALTER TABLE %s ADD IF NOT EXISTS" % table_fqn]
        for day in batch:
            ymd = ("%04d" % day.year, "%02d" % day.month, "%02d" % day.day)
            location = s3_url(bucket, prefix, "AWSLogs", account_id, "CloudTrail",
                              region, *ymd, trailing_slash=True)
            lines.append("    PARTITION (year = '%s', month = '%s', day = '%s')"
                         " LOCATION '%s'" % (ymd[0], ymd[1], ymd[2], location))
        statements.append("\n".join(lines) + ";")
    return "\n\n".join(statements)


def wrap_accounts(accounts: Sequence[str], indent: str) -> str:
    """`--accounts a b c`, wrapped so the suggested command stays readable."""
    out, line = [], ""
    for acct in accounts:
        if line and len(line) + len(acct) + 1 > 76:
            out.append(line)
            line = ""
        line = acct if not line else line + " " + acct
    if line:
        out.append(line)
    return (" \\\n" + indent).join(out)


def suggested_command(trail: Trail, variant: str, table: str) -> List[str]:
    style = VARIANTS[variant][2]
    end = trail.end_concrete
    lines = [
        "./scp_to_athena.py --scp-dir scps \\",
        "    --database %s --table %s \\" % (trail.database, table),
        "    --partition-style %s \\" % style,
        "    --start %s --end %s \\" % (trail.start, end),
    ]
    if variant == "org" and trail.accounts:
        lines.append("    --accounts %s \\" % wrap_accounts(trail.accounts, "        "))
    lines.append("    --out-dir athena-queries")
    return lines


def header(trail: Trail, template_name: str, generated: str,
           variant: Optional[str] = None, table: Optional[str] = None) -> str:
    lines = [
        "-- Rendered by render_ddl.py from athena-ddl/%s on %s." % (template_name,
                                                                    generated),
        "-- Trail %r from the CSV. Re-render after a CSV change; do not hand-edit."
        % trail.name,
    ]
    if variant and table:
        lines.append("--")
        lines.append("-- Then point the query generator at it:")
        lines.extend("--   " + line for line in suggested_command(trail, variant, table))
    return "\n".join(lines) + "\n\n"


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def load_template(template_dir: str, name: str) -> str:
    path = os.path.join(template_dir, name)
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise SystemExit("cannot read template %s: %s" % (path, exc))
    stray = {t for t in PLACEHOLDER_RE.findall(text)
             if t not in KNOWN_PLACEHOLDERS and t not in PROSE_PLACEHOLDERS}
    if stray:
        raise SystemExit("%s: unknown placeholder(s) %s -- fix the template or add "
                         "them to KNOWN_PLACEHOLDERS" % (path, ", ".join(sorted(stray))))
    return text


def render(text: str, mapping: Dict[str, str], where: str) -> str:
    text = TEMPLATE_ONLY_RE.sub("", text)
    while "\n--\n--\n" in text:  # the removed block leaves a doubled spacer
        text = text.replace("\n--\n--\n", "\n--\n")
    prefix = mapping.get("<PREFIX>", "")
    if not prefix:
        # Collapse the path segment rather than leaving an empty one behind.
        text = text.replace("/<PREFIX>/", "/")
    for token, value in mapping.items():
        text = text.replace(token, value)
    left = [t for t in KNOWN_PLACEHOLDERS if t in text]
    if left:
        raise SystemExit("%s: placeholder(s) %s were never filled in"
                         % (where, ", ".join(left)))
    return text


def mapping_for(trail: Trail, variant: Optional[str]) -> Dict[str, str]:
    mapping = {
        "<DATABASE>": trail.database,
        "<BUCKET>": trail.bucket,
        "<PREFIX>": trail.prefix,
        "<ACCOUNT_ID>": trail.account_id,
        "<ORG_ID>": trail.org_id,
        "<REGION>": trail.region,
        "<REGIONS>": ",".join(trail.regions),
        "<ACCOUNT_IDS>": ",".join(trail.accounts),
        "<RANGE_START>": trail.start.strftime("%Y/%m/%d"),
        "<RANGE_END>": trail.end.strftime("%Y/%m/%d") if trail.end else "NOW",
        "<WINDOW_START>": trail.start.isoformat(),
        "<WINDOW_END>": trail.end_concrete.isoformat(),
        "<TABLE>": trail.table,
    }
    if variant is None:
        return mapping

    table = trail.table_for(variant)
    style = VARIANTS[variant][2]
    # The trail's last full day is the safest sample: today's partition is only
    # partially written, and CloudTrail delivery lags by minutes either way.
    sample = min(trail.end_concrete, dt.date.today() - dt.timedelta(days=1))
    if sample < trail.start:
        sample = trail.start
    mapping.update({
        "<TABLE>": table,
        "<SAMPLE_DAY_PREDICATE>": day_predicate(style, sample),
        "<WINDOW_PREDICATE>": window_predicate(style, trail.start,
                                               trail.end_concrete),
    })
    if variant == "ymd":
        mapping["<ADD_PARTITIONS>"] = add_partitions_sql(
            "%s.%s" % (trail.database, table), trail.bucket, trail.prefix,
            trail.account_id, trail.region, trail.start, trail.end_concrete)
    return mapping


def render_trail(trail: Trail, template_dir: str, generated: str,
                 only: Optional[Sequence[str]]) -> List[Tuple[str, str]]:
    """Return [(filename, sql)] for one CSV row."""
    variants = trail.variants()
    if only:
        variants = [v for v in variants if v in only]
    if not variants:
        return []

    out: List[Tuple[str, str]] = []
    db_template = load_template(template_dir, DB_TEMPLATE)
    out.append((DB_TEMPLATE,
                header(trail, DB_TEMPLATE, generated)
                + render(db_template, mapping_for(trail, None),
                         "%s/%s" % (trail.name, DB_TEMPLATE))))

    validate_template = load_template(template_dir, VALIDATE_TEMPLATE)
    for variant in variants:
        template_name = VARIANTS[variant][0]
        table = trail.table_for(variant)
        mapping = mapping_for(trail, variant)
        out.append((template_name,
                    header(trail, template_name, generated, variant, table)
                    + render(load_template(template_dir, template_name), mapping,
                             "%s/%s" % (trail.name, template_name))))
        validate_name = "05_validate_%s.sql" % variant
        out.append((validate_name,
                    header(trail, VALIDATE_TEMPLATE, generated)
                    + render(validate_template, mapping,
                             "%s/%s" % (trail.name, validate_name))))
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

EXAMPLE_CSV = """\
name,bucket,prefix,account_id,org_id,accounts,region,regions,start_date,end_date,database,table,styles
# org trail: every member account, every commercial region, open-ended range
prod-org,acme-cloudtrail-logs,,,o-abc1234567,111111111111 222222222222 333333333333,,,2025-06-01,,cloudtrail,cloudtrail_logs,
# one account, trail under a prefix, only the regions this account is allowed in
sandbox,acme-sandbox-trail,trails/sandbox,444444444444,,,us-east-1,us-east-1 us-west-2,2025-06-01,2025-09-09,cloudtrail,sandbox_logs,
# same account again, manual partitions only -- single region by construction
sandbox-ymd,acme-sandbox-trail,trails/sandbox,444444444444,,,us-east-1,,2025-09-01,2025-09-09,cloudtrail,sandbox_logs,ymd
"""


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render the CloudTrail Athena DDL templates from a CSV.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="CSV columns: " + ", ".join(COLUMNS))
    parser.add_argument("csv", nargs="?", help="CSV of trails to render")
    parser.add_argument("--out-dir", default=os.path.join(HERE, "rendered"),
                        help="write <out-dir>/<name>/*.sql (default: %(default)s)")
    parser.add_argument("--template-dir", default=HERE,
                        help="where the numbered .sql templates live")
    parser.add_argument("--only", action="append", choices=sorted(VARIANTS),
                        help="render only this variant; repeatable")
    parser.add_argument("--stdout", action="store_true",
                        help="print to stdout instead of writing files")
    parser.add_argument("--force", action="store_true",
                        help="overwrite existing rendered files")
    parser.add_argument("--example-csv", action="store_true",
                        help="print a starter CSV and exit")
    parser.add_argument("--print-regions", action="store_true",
                        help="print the default region enum and exit")
    args = parser.parse_args(argv)

    if args.example_csv:
        sys.stdout.write(EXAMPLE_CSV)
        return 0
    if args.print_regions:
        print(",".join(ALL_REGIONS))
        return 0
    if not args.csv:
        parser.error("a CSV path is required (try --example-csv)")

    today = dt.date.today()
    try:
        trails = read_trails(args.csv, today)
    except CsvError as exc:
        sys.stderr.write("%s\n" % exc)
        return 2
    except OSError as exc:
        sys.stderr.write("cannot read %s: %s\n" % (args.csv, exc))
        return 2

    generated = today.isoformat()
    rendered = [(t, render_trail(t, args.template_dir, generated, args.only))
                for t in trails]

    for trail, files in rendered:
        for warning in trail.warnings():
            sys.stderr.write("warning: %s: %s\n" % (trail.name, warning))
        if not files:
            sys.stderr.write("warning: %s: nothing to render%s\n"
                             % (trail.name,
                                " for --only " + ",".join(args.only) if args.only
                                else " -- set account_id and/or org_id"))

    if args.stdout:
        for trail, files in rendered:
            for name, sql in files:
                print("-- ======== %s/%s ========" % (trail.name, name))
                print(sql.rstrip("\n"))
                print()
        return 0

    clashes = []
    for trail, files in rendered:
        for name, _ in files:
            path = os.path.join(args.out_dir, trail.name, name)
            if os.path.exists(path):
                clashes.append(path)
    if clashes and not args.force:
        sys.stderr.write("refusing to overwrite %d existing file(s); pass --force:\n%s\n"
                         % (len(clashes), "\n".join("  " + p for p in clashes[:10])))
        return 1

    written = 0
    for trail, files in rendered:
        directory = os.path.join(args.out_dir, trail.name)
        if files:
            os.makedirs(directory, exist_ok=True)
        for name, sql in files:
            with open(os.path.join(directory, name), "w", encoding="utf-8") as fh:
                fh.write(sql)
            written += 1
        if files:
            variants = sorted({n for n, _ in files})
            sys.stderr.write("%s -> %s (%s)\n"
                             % (trail.name, directory, ", ".join(variants)))
    sys.stderr.write("%d file(s) written\n" % written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
