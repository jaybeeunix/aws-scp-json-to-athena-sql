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
  ./run_sql.py --work-group scp-impact --jobs 8 rendered/big-org/07_compact_backfill.sql
  ./run_sql.py --dry-run rendered/prod-org/04_cloudtrail_logs_ymd_manual.sql

Stops at the first failed statement unless --continue-on-error: in a DDL file
the later statements usually depend on the earlier ones.

--jobs N runs independent statements concurrently. A compaction backfill is a
hundred-odd INSERTs that do not depend on each other and take minutes each, so
serially it is an afternoon. Only runs of consecutive SELECT/WITH/INSERT
statements are parallelised; anything else -- CREATE, ALTER, DROP -- is a
barrier that runs alone, in order, because the statements after it usually
depend on it. So a file of 101 INSERTs followed by a reconciling SELECT still
runs the SELECT last, and a CREATE-then-ALTER DDL file is unaffected by --jobs.

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
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Sequence, Tuple

TERMINAL = ("SUCCEEDED", "FAILED", "CANCELLED")
# Statements whose results are worth printing rather than just acknowledging.
ROW_PRODUCING = ("select", "with", "show", "describe", "desc", "explain", "values")
# Statements safe to run alongside each other. Reads are trivially safe; INSERT is
# here because the backfill's are disjoint by construction -- one per partition --
# and that is the case --jobs exists for. Everything else is treated as a barrier.
PARALLEL_SAFE = ("select", "with", "insert")


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

def format_table(rows: List[List[str]], limit: int) -> str:
    """Rendered as a string, not printed: with --jobs the caller prints whole
    statement reports atomically so concurrent ones do not interleave."""
    if not rows:
        return "      (no rows)"
    shown = rows[:limit + 1]
    widths: Dict[int, int] = {}
    for row in shown:
        for i, cell in enumerate(row):
            widths[i] = min(max(widths.get(i, 0), len(cell)), 40)
    out: List[str] = []
    for n, row in enumerate(shown):
        cells = [cell[:40].ljust(widths.get(i, 0)) for i, cell in enumerate(row)]
        out.append("      " + " | ".join(cells).rstrip())
        if n == 0:
            out.append("      " + "-+-".join("-" * widths.get(i, 0)
                                             for i in range(len(row))))
    if len(rows) > limit + 1:
        out.append("      ... (more rows in the result file)")
    return "\n".join(out)


def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return "%.0f %s" % (size, unit) if unit == "B" else "%.1f %s" % (size, unit)
        size /= 1024
    return "%d B" % n


# ---------------------------------------------------------------------------

def parallel_blocks(statements: Sequence[str],
                    jobs: int) -> List[Tuple[bool, List[int]]]:
    """Group statement indices into [(run_in_parallel, [index, ...]), ...].

    A block is a run of consecutive statements with the SAME PARALLEL_SAFE keyword.
    Anything else -- a different keyword, or one not in PARALLEL_SAFE -- starts a new
    block, and blocks always run in order.

    Same-keyword, not just same-safety, because the mix is where the hazard is. The
    backfill is 101 INSERTs followed by a SELECT that counts what they wrote; both
    keywords are individually safe to parallelise, but running the SELECT alongside
    the INSERTs would have it count a half-written table. Grouping by keyword puts
    the INSERTs in one concurrent block and the SELECT in the next, after them.
    """
    blocks: List[Tuple[str, List[int]]] = []
    for index, statement in enumerate(statements):
        keyword = first_keyword(statement)
        safe = jobs > 1 and keyword in PARALLEL_SAFE
        if safe and blocks and blocks[-1][0] == keyword:
            blocks[-1][1].append(index)
        else:
            blocks.append((keyword if safe else "", [index]))
    # A "parallel" block of one is just a serial statement; label it so.
    return [(bool(keyword) and len(items) > 1, items) for keyword, items in blocks]


def run_statement(athena: Athena, path: str, statement: str, number: int,
                  total: int, args: argparse.Namespace) -> Tuple[bool, str]:
    """Submit one statement and wait. Returns (succeeded, text to print).

    Output is buffered rather than printed, so that concurrent statements each
    land as one readable block instead of interleaving line by line.
    """
    out = ["  [%d/%d] %s" % (number, total, summarize(statement))]
    try:
        qid = athena.start(statement)
        execution = athena.wait(qid, args.timeout)
    except AwsError as exc:
        out.append("        ERROR %s" % exc)
        return False, "\n".join(out)

    status = execution["Status"]
    stats = execution.get("Statistics", {})
    scanned = stats.get("DataScannedInBytes", 0)
    millis = stats.get("EngineExecutionTimeInMillis", 0)
    state = status["State"]
    out.append("        %s in %.1fs, %s scanned  [%s]"
               % (state, millis / 1000.0, human_bytes(scanned), qid))

    if state != "SUCCEEDED":
        out.append("        %s" % status.get("StateChangeReason", "(no reason given)"))
        return False, "\n".join(out)

    if args.max_results and returns_rows(statement):
        try:
            out.append(format_table(athena.results(qid, args.max_results),
                                    args.max_results))
        except AwsError as exc:
            out.append("        (results unavailable: %s)" % exc)
    if args.save_results:
        location = execution.get("ResultConfiguration", {}).get("OutputLocation")
        if location:
            os.makedirs(args.save_results, exist_ok=True)
            dest = os.path.join(
                args.save_results,
                "%s_%02d_%s.csv" % (os.path.basename(path).rsplit(".", 1)[0],
                                    number, qid))
            subprocess.run(athena.base + ["s3", "cp", location, dest],
                           stdout=subprocess.DEVNULL)
            out.append("        saved %s" % dest)
    return True, "\n".join(out)


def run_file(athena: Athena, path: str, args: argparse.Namespace) -> Tuple[int, int]:
    try:
        with open(path, encoding="utf-8") as fh:
            statements = split_statements(fh.read())
    except OSError as exc:
        print("cannot read %s: %s" % (path, exc), file=sys.stderr)
        return (0, 1)

    total = len(statements)
    print("\n== %s -- %d statement(s)" % (path, total))

    if args.dry_run:
        for number, statement in enumerate(statements, 1):
            print("  [%d/%d] %s" % (number, total, summarize(statement)))
        return (0, 0)

    ok = failed = 0
    for concurrent, indices in parallel_blocks(statements, args.jobs):
        if not concurrent:
            index = indices[0]
            succeeded, text = run_statement(athena, path, statements[index],
                                            index + 1, total, args)
            print(text, flush=True)
            ok, failed = (ok + 1, failed) if succeeded else (ok, failed + 1)
            if not succeeded and not args.continue_on_error:
                return (ok, failed)
            continue

        width = min(args.jobs, len(indices))
        print("  -- %d statements, %d at a time" % (len(indices), width), flush=True)
        # Let every statement in the block finish before deciding whether to stop.
        # Cancelling in flight would leave an INSERT's partial output behind without
        # telling you which partition to clean up; a full report does tell you.
        with ThreadPoolExecutor(max_workers=width) as pool:
            results = list(pool.map(
                lambda index: run_statement(athena, path, statements[index],
                                            index + 1, total, args),
                indices))
        block_failed = 0
        for succeeded, text in results:
            print(text, flush=True)
            if succeeded:
                ok += 1
            else:
                failed += 1
                block_failed += 1
        if block_failed:
            print("  -- %d of %d statements in this block failed; re-run only those,"
                  % (block_failed, len(indices)))
            print("  -- and for INSERTs delete the target partition first (appends "
                  "are not idempotent)")
            if not args.continue_on_error:
                return (ok, failed)
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
    parser.add_argument("--jobs", type=int, default=1, metavar="N",
                        help="run up to N independent statements at once (default: "
                             "%(default)s). Only consecutive SELECT/WITH/INSERT "
                             "statements are parallelised; DDL stays serial. Athena's "
                             "default DML concurrency quota is 20-25, so leave "
                             "headroom -- 8 is a good value for a backfill")
    parser.add_argument("--continue-on-error", action="store_true")
    parser.add_argument("--dry-run", action="store_true",
                        help="list the statements without running them")
    args = parser.parse_args(argv)

    if args.jobs < 1:
        parser.error("--jobs must be at least 1")
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
