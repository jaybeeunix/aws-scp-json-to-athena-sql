#!/usr/bin/env python3
"""
run_sql.py -- run a .sql file through Athena with the aws CLI.

Athena's StartQueryExecution takes one statement, but these files hold several:
04_*.sql is a CREATE plus batched ALTER ... ADD PARTITION, 05_validate_*.sql is
five SELECTs, and the queries scp_to_athena.py writes are a SUMMARY plus a
DETAIL. This splits a file into statements -- quote- and comment-aware, so a
`;` inside a string or a `--` comment does not end one -- then submits each in
order, waits, and reports state, bytes scanned and (for statements that return
rows) the first few rows.

Usage
-----
  ./run_sql.py --work-group scp-impact rendered/prod-org/*.sql
  ./run_sql.py --output-location s3://my-results/ ../athena-queries/*.sql
  ./run_sql.py --dry-run rendered/prod-org/04_cloudtrail_logs_ymd_manual.sql

Stops at the first failed statement unless --continue-on-error: in a DDL file
the later statements usually depend on the earlier ones.

Python 3.8+, standard library only. Shells out to `aws`, so it uses whatever
credentials, profile and region the CLI is already configured with.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Dict, List, Optional, Sequence, Tuple

TERMINAL = ("SUCCEEDED", "FAILED", "CANCELLED")
# Statements whose results are worth printing rather than just acknowledging.
ROW_PRODUCING = ("select", "with", "show", "describe", "desc", "explain", "values")


# ---------------------------------------------------------------------------
# splitting
# ---------------------------------------------------------------------------

def split_statements(sql: str) -> List[str]:
    """Split on `;`, ignoring ones inside strings, identifiers or comments.

    Statements keep their comments -- they show up in Athena's query history,
    which is where you look when a result is surprising a week later.
    """
    statements: List[str] = []
    buf: List[str] = []
    i, n = 0, len(sql)
    quote: Optional[str] = None  # "'" or '"' when inside one
    comment: Optional[str] = None  # "line" or "block"

    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        if comment == "line":
            buf.append(ch)
            if ch == "\n":
                comment = None
            i += 1
            continue
        if comment == "block":
            buf.append(ch)
            if ch == "*" and nxt == "/":
                buf.append(nxt)
                comment = None
                i += 2
                continue
            i += 1
            continue
        if quote is not None:
            buf.append(ch)
            if ch == quote:
                if nxt == quote:  # '' or "" is an escaped quote, not the end
                    buf.append(nxt)
                    i += 2
                    continue
                quote = None
            i += 1
            continue

        if ch == "-" and nxt == "-":
            comment = "line"
            buf.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "*":
            comment = "block"
            buf.append(ch)
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == ";":
            statements.append("".join(buf))
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    statements.append("".join(buf))
    return [s for s in (t.strip() for t in statements) if has_sql(s)]


def strip_comments(sql: str) -> str:
    """The statement with comments blanked out -- for emptiness and kind checks."""
    out: List[str] = []
    i, n = 0, len(sql)
    quote: Optional[str] = None
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if quote is not None:
            out.append(ch)
            if ch == quote:
                if nxt == quote:
                    out.append(nxt)
                    i += 2
                    continue
                quote = None
            i += 1
            continue
        if ch == "-" and nxt == "-":
            while i < n and sql[i] != "\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i < n and not (sql[i] == "*" and i + 1 < n and sql[i + 1] == "/"):
                i += 1
            i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
        out.append(ch)
        i += 1
    return "".join(out)


def has_sql(statement: str) -> bool:
    return bool(strip_comments(statement).strip())


def first_keyword(statement: str) -> str:
    body = strip_comments(statement).strip()
    return body.split()[0].lower().strip("(") if body else ""


def returns_rows(statement: str) -> bool:
    return first_keyword(statement) in ROW_PRODUCING


def summarize(statement: str, width: int = 68) -> str:
    """A one-line label for progress output."""
    body = " ".join(strip_comments(statement).split())
    return body[:width] + (" ..." if len(body) > width else "")


# ---------------------------------------------------------------------------
# aws CLI
# ---------------------------------------------------------------------------

class AwsError(Exception):
    pass


class Athena:
    def __init__(self, args: argparse.Namespace) -> None:
        self.base = ["aws"]
        if args.profile:
            self.base += ["--profile", args.profile]
        if args.region:
            self.base += ["--region", args.region]
        self.args = args

    def _run(self, params: Sequence[str]) -> dict:
        cmd = self.base + ["athena"] + list(params) + ["--output", "json"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            raise AwsError(proc.stderr.decode("utf-8", "replace").strip()
                           or "aws exited %d" % proc.returncode)
        out = proc.stdout.decode("utf-8", "replace").strip()
        return json.loads(out) if out else {}

    def start(self, statement: str) -> str:
        # `--opt=value`, not `--opt value`: these statements begin with a `--`
        # comment, which the CLI's parser would otherwise read as an option.
        params = ["start-query-execution", "--query-string=" + statement]
        if self.args.work_group:
            params += ["--work-group", self.args.work_group]
        if self.args.output_location:
            params += ["--result-configuration",
                       "OutputLocation=" + self.args.output_location]
        if self.args.database:
            ctx = "Database=" + self.args.database
            if self.args.catalog:
                ctx += ",Catalog=" + self.args.catalog
            params += ["--query-execution-context", ctx]
        return self._run(params)["QueryExecutionId"]

    def wait(self, qid: str, timeout: int) -> dict:
        deadline = time.time() + timeout
        delay = 1.0
        while True:
            execution = self._run(["get-query-execution",
                                   "--query-execution-id", qid])["QueryExecution"]
            state = execution["Status"]["State"]
            if state in TERMINAL:
                return execution
            if time.time() > deadline:
                raise AwsError("still %s after %ds; cancel it with "
                               "`aws athena stop-query-execution "
                               "--query-execution-id %s`" % (state, timeout, qid))
            time.sleep(delay)
            delay = min(delay * 1.5, 5.0)

    def results(self, qid: str, limit: int) -> List[List[str]]:
        page = self._run(["get-query-results", "--query-execution-id", qid,
                          "--max-items", str(limit + 1)])
        rows = []
        for row in page.get("ResultSet", {}).get("Rows", []):
            rows.append([cell.get("VarCharValue", "") for cell in row.get("Data", [])])
        return rows


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------

def print_table(rows: List[List[str]], limit: int) -> None:
    if not rows:
        print("      (no rows)")
        return
    shown = rows[:limit + 1]
    widths: Dict[int, int] = {}
    for row in shown:
        for i, cell in enumerate(row):
            widths[i] = min(max(widths.get(i, 0), len(cell)), 40)
    for n, row in enumerate(shown):
        cells = [cell[:40].ljust(widths.get(i, 0)) for i, cell in enumerate(row)]
        print("      " + " | ".join(cells).rstrip())
        if n == 0:
            print("      " + "-+-".join("-" * widths.get(i, 0)
                                        for i in range(len(row))))
    if len(rows) > limit + 1:
        print("      ... (more rows in the result file)")


def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return "%.0f %s" % (size, unit) if unit == "B" else "%.1f %s" % (size, unit)
        size /= 1024
    return "%d B" % n


# ---------------------------------------------------------------------------

def run_file(athena: Athena, path: str, args: argparse.Namespace) -> Tuple[int, int]:
    try:
        with open(path, encoding="utf-8") as fh:
            statements = split_statements(fh.read())
    except OSError as exc:
        print("cannot read %s: %s" % (path, exc), file=sys.stderr)
        return (0, 1)

    print("\n== %s -- %d statement(s)" % (path, len(statements)))
    ok = failed = 0
    for n, statement in enumerate(statements, 1):
        label = "  [%d/%d] %s" % (n, len(statements), summarize(statement))
        if args.dry_run:
            print(label)
            continue
        print(label, flush=True)
        try:
            qid = athena.start(statement)
            execution = athena.wait(qid, args.timeout)
        except AwsError as exc:
            print("        ERROR %s" % exc)
            failed += 1
            if not args.continue_on_error:
                return (ok, failed)
            continue

        status = execution["Status"]
        stats = execution.get("Statistics", {})
        scanned = stats.get("DataScannedInBytes", 0)
        millis = stats.get("EngineExecutionTimeInMillis", 0)
        state = status["State"]
        print("        %s in %.1fs, %s scanned  [%s]"
              % (state, millis / 1000.0, human_bytes(scanned), qid))

        if state != "SUCCEEDED":
            reason = status.get("StateChangeReason", "(no reason given)")
            print("        %s" % reason)
            failed += 1
            if not args.continue_on_error:
                return (ok, failed)
            continue

        ok += 1
        if args.max_results and returns_rows(statement):
            try:
                print_table(athena.results(qid, args.max_results), args.max_results)
            except AwsError as exc:
                print("        (results unavailable: %s)" % exc)
        if args.save_results:
            location = execution.get("ResultConfiguration", {}).get("OutputLocation")
            if location:
                os.makedirs(args.save_results, exist_ok=True)
                dest = os.path.join(
                    args.save_results,
                    "%s_%02d_%s.csv" % (os.path.basename(path).rsplit(".", 1)[0],
                                        n, qid))
                subprocess.run(athena.base + ["s3", "cp", location, dest],
                               stdout=subprocess.DEVNULL)
                print("        saved %s" % dest)
    return (ok, failed)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run .sql files through Athena, one statement at a time.")
    parser.add_argument("files", nargs="+", help=".sql files, run in the order given")
    parser.add_argument("--work-group", help="Athena workgroup")
    parser.add_argument("--output-location",
                        help="s3:// results prefix; required unless the workgroup "
                             "enforces one")
    parser.add_argument("--database", help="default database for unqualified names "
                                           "(the generated SQL is fully qualified)")
    parser.add_argument("--catalog", default="AwsDataCatalog")
    parser.add_argument("--profile")
    parser.add_argument("--region")
    parser.add_argument("--timeout", type=int, default=600,
                        help="seconds to wait per statement (default: %(default)s)")
    parser.add_argument("--max-results", type=int, default=20,
                        help="rows to print per query, 0 to skip (default: %(default)s)")
    parser.add_argument("--save-results", metavar="DIR",
                        help="also download each result CSV into DIR")
    parser.add_argument("--continue-on-error", action="store_true")
    parser.add_argument("--dry-run", action="store_true",
                        help="list the statements without running them")
    args = parser.parse_args(argv)

    if not args.dry_run and not (args.work_group or args.output_location):
        parser.error("pass --work-group or --output-location: Athena has nowhere "
                     "to write results otherwise")

    athena = Athena(args)
    total_ok = total_failed = 0
    for path in args.files:
        ok, failed = run_file(athena, path, args)
        total_ok += ok
        total_failed += failed
        if failed and not args.continue_on_error:
            break

    if not args.dry_run:
        print("\n%d succeeded, %d failed" % (total_ok, total_failed))
    return 1 if total_failed else 0


if __name__ == "__main__":
    sys.exit(main())
