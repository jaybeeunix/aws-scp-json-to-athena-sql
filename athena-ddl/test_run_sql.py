#!/usr/bin/env python3
"""Tests for run_sql.py -- the statement splitter and the CLI wiring.

  cd athena-ddl && python3 -m unittest test_run_sql

Nothing here calls AWS: the splitter is pure, and the one end-to-end test runs
with --dry-run.
"""

from __future__ import annotations

import contextlib
import io
import os
import unittest

import run_sql as rs

HERE = os.path.dirname(os.path.abspath(__file__))


class Split(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(rs.split_statements("SELECT 1; SELECT 2;"),
                         ["SELECT 1", "SELECT 2"])

    def test_trailing_semicolon_is_not_an_empty_statement(self):
        self.assertEqual(len(rs.split_statements("SELECT 1;\n")), 1)

    def test_missing_trailing_semicolon(self):
        self.assertEqual(rs.split_statements("SELECT 1"), ["SELECT 1"])

    def test_semicolon_in_string_literal(self):
        stmts = rs.split_statements("SELECT ';' AS x; SELECT 2")
        self.assertEqual(stmts, ["SELECT ';' AS x", "SELECT 2"])

    def test_semicolon_in_line_comment(self):
        stmts = rs.split_statements("-- run this; then that\nSELECT 1;")
        self.assertEqual(len(stmts), 1)
        self.assertIn("run this; then that", stmts[0])

    def test_semicolon_in_block_comment(self):
        stmts = rs.split_statements("SELECT /* a; b */ 1; SELECT 2")
        self.assertEqual(len(stmts), 2)

    def test_semicolon_in_quoted_identifier(self):
        stmts = rs.split_statements('SELECT "we;ird" FROM t; SELECT 2')
        self.assertEqual(len(stmts), 2)

    def test_escaped_quote_inside_string(self):
        stmts = rs.split_statements("SELECT 'it''s; fine' AS x; SELECT 2")
        self.assertEqual(stmts[0], "SELECT 'it''s; fine' AS x")
        self.assertEqual(len(stmts), 2)

    def test_comment_only_file_yields_nothing(self):
        self.assertEqual(rs.split_statements("-- just a note\n\n"), [])

    def test_comments_are_kept_with_the_statement(self):
        stmts = rs.split_statements("-- why\nSELECT 1;")
        self.assertTrue(stmts[0].startswith("-- why"))

    def test_generator_ymd_predicate_survives(self):
        # lpad(...,'0') and the '/' separators are the splitter's worst case.
        sql = ("SELECT 1 FROM t WHERE concat(\"year\", '/', lpad(\"month\", 2, '0'))"
               " BETWEEN '2025/06/01' AND '2025/09/09';")
        self.assertEqual(len(rs.split_statements(sql)), 1)


class Classify(unittest.TestCase):
    def test_strip_comments(self):
        self.assertEqual(rs.strip_comments("a -- b\nc").strip(), "a \nc".strip())

    def test_strip_block_comment(self):
        self.assertEqual(rs.strip_comments("TRUE /* unevaluable */ AND x").split(),
                         ["TRUE", "AND", "x"])

    def test_does_not_strip_inside_a_string(self):
        self.assertIn("--", rs.strip_comments("SELECT 'a -- b'"))

    def test_first_keyword_skips_comments(self):
        self.assertEqual(rs.first_keyword("-- hi\n  CREATE EXTERNAL TABLE t"), "create")

    def test_returns_rows(self):
        self.assertTrue(rs.returns_rows("-- c\nSELECT 1"))
        self.assertTrue(rs.returns_rows("WITH a AS (SELECT 1) SELECT * FROM a"))
        self.assertFalse(rs.returns_rows("CREATE DATABASE d"))
        self.assertFalse(rs.returns_rows("ALTER TABLE t ADD PARTITION (a='1')"))

    def test_summarize_collapses_whitespace_and_comments(self):
        self.assertEqual(rs.summarize("-- note\nSELECT\n   1"), "SELECT 1")


class RealFiles(unittest.TestCase):
    """The templates themselves are not runnable, but their structure matters."""

    def test_validate_template_has_five_statements(self):
        with open(os.path.join(HERE, "05_validate.sql"), encoding="utf-8") as fh:
            self.assertEqual(len(rs.split_statements(fh.read())), 5)

    def test_create_table_templates_are_one_statement(self):
        for name in ("01_create_database.sql", "02_cloudtrail_logs_projection.sql",
                     "03_cloudtrail_logs_org_projection.sql"):
            with open(os.path.join(HERE, name), encoding="utf-8") as fh:
                with self.subTest(name=name):
                    self.assertEqual(len(rs.split_statements(fh.read())), 1)

    def test_statements_keep_their_semicolons_off(self):
        with open(os.path.join(HERE, "05_validate.sql"), encoding="utf-8") as fh:
            for statement in rs.split_statements(fh.read()):
                self.assertFalse(statement.rstrip().endswith(";"))


class Cli(unittest.TestCase):
    def test_requires_a_results_destination(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                rs.main(["x.sql"])

    def test_dry_run_lists_statements(self):
        path = os.path.join(HERE, "05_validate.sql")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(rs.main(["--dry-run", path]), 0)
        self.assertIn("5 statement(s)", out.getvalue())
        self.assertIn("[5/5]", out.getvalue())

    def test_missing_file_is_reported_not_raised(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = rs.main(["--dry-run", os.path.join(HERE, "nope.sql")])
        self.assertEqual(rc, 1)
        self.assertIn("cannot read", err.getvalue())


class Humanize(unittest.TestCase):
    def test_bytes(self):
        self.assertEqual(rs.human_bytes(0), "0 B")
        self.assertEqual(rs.human_bytes(2048), "2.0 KB")
        self.assertEqual(rs.human_bytes(5 * 1024 ** 3), "5.0 GB")


class ParallelBlocks(unittest.TestCase):
    @staticmethod
    def plan(statements, jobs):
        return [("par" if concurrent else "ser", len(indices))
                for concurrent, indices in rs.parallel_blocks(statements, jobs)]

    def test_jobs_one_keeps_everything_serial(self):
        self.assertEqual(self.plan(["INSERT INTO t VALUES (1)"] * 3, 1),
                         [("ser", 1)] * 3)

    def test_consecutive_inserts_share_a_block(self):
        self.assertEqual(self.plan(["INSERT INTO t VALUES (1)"] * 4, 8),
                         [("par", 4)])

    def test_a_trailing_select_waits_for_the_inserts(self):
        """The backfill's reconcile counts what the INSERTs wrote. Both keywords
        are parallel-safe on their own, so grouping by safety alone would run it
        against a half-written table."""
        statements = ["INSERT INTO t VALUES (1)"] * 3 + ["SELECT count(*) FROM t"]
        self.assertEqual(self.plan(statements, 8), [("par", 3), ("ser", 1)])

    def test_ddl_is_a_barrier(self):
        statements = ["CREATE TABLE t (a int)",
                      "INSERT INTO t VALUES (1)", "INSERT INTO t VALUES (2)",
                      "ALTER TABLE t ADD COLUMN b int",
                      "INSERT INTO t VALUES (3)"]
        self.assertEqual(self.plan(statements, 8),
                         [("ser", 1), ("par", 2), ("ser", 1), ("ser", 1)])

    def test_every_statement_runs_exactly_once_in_order(self):
        statements = ["CREATE TABLE t (a int)"] + \
                     ["INSERT INTO t VALUES (%d)" % n for n in range(5)] + \
                     ["SELECT 1", "SELECT 2"]
        for jobs in (1, 2, 8):
            flat = [i for _, indices in rs.parallel_blocks(statements, jobs)
                    for i in indices]
            self.assertEqual(flat, list(range(len(statements))), jobs)

    def test_lone_safe_statement_is_not_labelled_parallel(self):
        self.assertEqual(self.plan(["SELECT 1"], 8), [("ser", 1)])

    def test_comment_prefixed_statements_classify_on_the_sql(self):
        # Every generated file opens with a `--` banner; first_keyword has to see
        # past it or nothing would ever be parallelised.
        statements = ["-- banner\nINSERT INTO t VALUES (1)",
                      "-- banner\nINSERT INTO t VALUES (2)"]
        self.assertEqual(self.plan(statements, 4), [("par", 2)])


class FormatTable(unittest.TestCase):
    def test_returns_a_string_rather_than_printing(self):
        # With --jobs the caller prints a whole statement report at once; anything
        # that printed directly would interleave with the other workers.
        out = rs.format_table([["a", "b"], ["1", "2"]], 10)
        self.assertIsInstance(out, str)
        self.assertIn("a", out)
        self.assertIn("-+-", out)

    def test_no_rows(self):
        self.assertEqual(rs.format_table([], 10).strip(), "(no rows)")


class JobsCli(unittest.TestCase):
    def test_zero_jobs_is_rejected(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                rs.main(["--dry-run", "--jobs", "0", "x.sql"])

    def test_default_is_serial(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                with contextlib.redirect_stderr(io.StringIO()):
                    rs.main([])


if __name__ == "__main__":
    unittest.main()
