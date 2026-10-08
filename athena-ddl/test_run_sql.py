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


if __name__ == "__main__":
    unittest.main()
