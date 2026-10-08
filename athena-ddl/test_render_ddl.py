#!/usr/bin/env python3
"""Tests for render_ddl.py.

  cd athena-ddl && python3 -m unittest test_render_ddl

If sqlglot is installed the rendered SQL is also parse-checked against the
Athena dialect; those tests skip otherwise.
"""

from __future__ import annotations

import datetime as dt
import os
import tempfile
import unittest

import render_ddl as rd

try:
    import sqlglot
except ImportError:  # pragma: no cover - optional dependency
    sqlglot = None

TODAY = dt.date(2026, 10, 8)

HEADER = ("name,bucket,prefix,account_id,org_id,accounts,region,regions,"
          "start_date,end_date,database,table,styles,table_org\n")


def trail(**kwargs) -> rd.Trail:
    row = {"name": "t", "bucket": "b-bucket", "start_date": "2025-06-01"}
    row.update(kwargs)
    return rd.Trail(row, 2, TODAY)


def write_csv(body: str) -> str:
    fh = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False)
    fh.write(body)
    fh.close()
    return fh.name


class SplitList(unittest.TestCase):
    def test_separators(self):
        self.assertEqual(rd.split_list("a, b;c  d"), ["a", "b", "c", "d"])

    def test_dedupes_preserving_order(self):
        self.assertEqual(rd.split_list("b a b"), ["b", "a"])

    def test_empty(self):
        self.assertEqual(rd.split_list("   "), [])


class Dates(unittest.TestCase):
    def test_both_formats(self):
        self.assertEqual(rd.parse_date("2025-06-01", "f", 1), dt.date(2025, 6, 1))
        self.assertEqual(rd.parse_date("2025/06/01", "f", 1), dt.date(2025, 6, 1))

    def test_rejects_junk(self):
        with self.assertRaises(rd.CsvError):
            rd.parse_date("2025-13-01", "start_date", 7)

    def test_end_before_start(self):
        with self.assertRaises(rd.CsvError):
            trail(end_date="2025-01-01")

    def test_missing_start_date(self):
        with self.assertRaisesRegex(rd.CsvError, "start_date is required"):
            rd.Trail({"name": "t", "bucket": "b-bucket"}, 2, TODAY)


class Validation(unittest.TestCase):
    def test_name_charset(self):
        with self.assertRaises(rd.CsvError):
            trail(name="has space")

    def test_account_id_length(self):
        with self.assertRaises(rd.CsvError):
            trail(account_id="12345")

    def test_org_id_shape(self):
        with self.assertRaises(rd.CsvError):
            trail(org_id="o-BAD")

    def test_table_must_be_bare_identifier(self):
        with self.assertRaises(rd.CsvError):
            trail(table="a-b")

    def test_region_shape(self):
        with self.assertRaises(rd.CsvError):
            trail(region="nowhere")

    def test_defaults(self):
        t = trail()
        self.assertEqual(t.database, "cloudtrail")
        self.assertEqual(t.table, "cloudtrail_logs")
        self.assertEqual(t.regions, list(rd.ALL_REGIONS))


class Variants(unittest.TestCase):
    def test_account_only_gives_projection(self):
        self.assertEqual(trail(account_id="1" * 12).variants(), ["projection"])

    def test_account_and_region_add_ymd(self):
        t = trail(account_id="1" * 12, region="us-east-1")
        self.assertEqual(t.variants(), ["projection", "ymd"])

    def test_org_needs_accounts(self):
        self.assertEqual(trail(org_id="o-abc1234567").variants(), [])
        t = trail(org_id="o-abc1234567", accounts="1" * 12)
        self.assertEqual(t.variants(), ["org"])

    def test_explicit_style_without_variables_errors(self):
        with self.assertRaisesRegex(rd.CsvError, "org_id, accounts are not set"):
            trail(styles="org").variants()

    def test_unknown_style(self):
        with self.assertRaises(rd.CsvError):
            trail(styles="projectionn")

    def test_table_suffixes(self):
        t = trail(account_id="1" * 12, org_id="o-abc1234567")
        self.assertEqual(t.table_for("projection"), "cloudtrail_logs")
        self.assertEqual(t.table_for("org"), "cloudtrail_logs_org")
        self.assertEqual(t.table_for("ymd"), "cloudtrail_logs_ymd")

    def test_table_override(self):
        t = trail(table_org="custom_name")
        self.assertEqual(t.table_for("org"), "custom_name")


class Regions(unittest.TestCase):
    def test_no_govcloud_in_default_enum(self):
        self.assertFalse([r for r in rd.ALL_REGIONS if r.startswith("us-gov-")])

    def test_no_china_or_iso_in_default_enum(self):
        self.assertFalse([r for r in rd.ALL_REGIONS
                          if r.startswith("cn-") or "-iso" in r])

    def test_default_enum_is_sorted_and_unique(self):
        self.assertEqual(list(rd.ALL_REGIONS), sorted(set(rd.ALL_REGIONS)))

    def test_govcloud_override_warns(self):
        t = trail(regions="us-east-1 us-gov-west-1")
        self.assertTrue(any("GovCloud" in w for w in t.warnings()))

    def test_unknown_region_warns(self):
        self.assertTrue(any("xx-fake-9" in w for w in trail(regions="xx-fake-9").warnings()))


class Paths(unittest.TestCase):
    def test_s3_url_without_prefix(self):
        self.assertEqual(rd.s3_url("b", "", "AWSLogs"), "s3://b/AWSLogs")

    def test_s3_url_strips_slashes(self):
        self.assertEqual(rd.s3_url("b", "/p/", "AWSLogs", trailing_slash=True),
                         "s3://b/p/AWSLogs/")

    def test_empty_prefix_collapses_path_segment(self):
        out = rd.render("LOCATION 's3://<BUCKET>/<PREFIX>/AWSLogs/'",
                        {"<BUCKET>": "b", "<PREFIX>": ""}, "x")
        self.assertEqual(out, "LOCATION 's3://b/AWSLogs/'")

    def test_prefix_is_inserted(self):
        out = rd.render("LOCATION 's3://<BUCKET>/<PREFIX>/AWSLogs/'",
                        {"<BUCKET>": "b", "<PREFIX>": "p/q"}, "x")
        self.assertEqual(out, "LOCATION 's3://b/p/q/AWSLogs/'")


class Predicates(unittest.TestCase):
    def test_timestamp_day(self):
        self.assertEqual(rd.day_predicate("timestamp", dt.date(2025, 9, 1)),
                         "\"timestamp\" = '2025/09/01'")

    def test_ymd_day_zero_pads(self):
        self.assertEqual(rd.day_predicate("ymd", dt.date(2025, 9, 1)),
                         "\"year\" = '2025' AND \"month\" = '09' AND \"day\" = '01'")

    def test_timestamp_window(self):
        self.assertEqual(
            rd.window_predicate("timestamp", dt.date(2025, 6, 1), dt.date(2025, 9, 9)),
            "\"timestamp\" BETWEEN '2025/06/01' AND '2025/09/09'")

    def test_ymd_window_matches_generator_shape(self):
        # scp_to_athena.py emits exactly this concat/lpad form for --partition-style ymd.
        got = rd.window_predicate("ymd", dt.date(2025, 6, 1), dt.date(2025, 9, 9))
        self.assertIn("concat(\"year\", '/', lpad(\"month\", 2, '0'), "
                      "'/', lpad(\"day\", 2, '0'))", got)
        self.assertIn("BETWEEN '2025/06/01' AND '2025/09/09'", got)


class AddPartitions(unittest.TestCase):
    def test_one_day(self):
        sql = rd.add_partitions_sql("db.t", "b", "", "1" * 12, "us-east-1",
                                    dt.date(2025, 9, 1), dt.date(2025, 9, 1))
        self.assertIn("ALTER TABLE db.t ADD IF NOT EXISTS", sql)
        self.assertIn("PARTITION (year = '2025', month = '09', day = '01')", sql)
        self.assertIn("s3://b/AWSLogs/%s/CloudTrail/us-east-1/2025/09/01/" % ("1" * 12),
                      sql)
        self.assertEqual(sql.count("ALTER TABLE"), 1)

    def test_batches(self):
        start = dt.date(2025, 1, 1)
        end = start + dt.timedelta(days=rd.PARTITIONS_PER_STATEMENT)  # one over
        sql = rd.add_partitions_sql("db.t", "b", "p", "1" * 12, "us-east-1", start, end)
        self.assertEqual(sql.count("ALTER TABLE"), 2)
        self.assertEqual(sql.count("PARTITION ("), rd.PARTITIONS_PER_STATEMENT + 1)
        self.assertEqual(sql.count(";"), 2)

    def test_prefix_in_partition_location(self):
        sql = rd.add_partitions_sql("db.t", "b", "trails/x", "1" * 12, "eu-west-1",
                                    dt.date(2025, 9, 1), dt.date(2025, 9, 1))
        self.assertIn("s3://b/trails/x/AWSLogs/", sql)


class Rendering(unittest.TestCase):
    def test_every_template_loads(self):
        for name in [rd.DB_TEMPLATE, rd.VALIDATE_TEMPLATE] + [
                v[0] for v in rd.VARIANTS.values()]:
            rd.load_template(rd.HERE, name)  # raises on an unknown placeholder

    def test_template_only_block_is_dropped(self):
        text = "a\n-- TEMPLATE-ONLY BEGIN\n-- help\n-- TEMPLATE-ONLY END\nb\n"
        self.assertEqual(rd.render(text, {}, "x"), "a\nb\n")

    def test_unfilled_placeholder_is_fatal(self):
        with self.assertRaises(SystemExit):
            rd.render("SELECT * FROM <DATABASE>.<TABLE>", {"<DATABASE>": "d"}, "x")

    def test_account_ids_token_not_eaten_by_account_id(self):
        out = rd.render("<ACCOUNT_ID>|<ACCOUNT_IDS>",
                        {"<ACCOUNT_ID>": "A", "<ACCOUNT_IDS>": "B"}, "x")
        self.assertEqual(out, "A|B")

    def test_open_ended_range_becomes_now(self):
        m = rd.mapping_for(trail(account_id="1" * 12), "projection")
        self.assertEqual(m["<RANGE_END>"], "NOW")
        self.assertEqual(m["<RANGE_START>"], "2025/06/01")

    def test_explicit_end_date_bounds_range(self):
        m = rd.mapping_for(trail(account_id="1" * 12, end_date="2025-09-09"),
                           "projection")
        self.assertEqual(m["<RANGE_END>"], "2025/09/09")

    def test_sample_day_is_inside_the_window(self):
        t = trail(account_id="1" * 12, end_date="2025-09-09")
        m = rd.mapping_for(t, "projection")
        self.assertEqual(m["<SAMPLE_DAY_PREDICATE>"], "\"timestamp\" = '2025/09/09'")

    def test_files_for_a_row(self):
        t = trail(account_id="1" * 12, org_id="o-abc1234567", accounts="2" * 12,
                  region="us-east-1")
        names = [n for n, _ in rd.render_trail(t, rd.HERE, "2026-10-08", None)]
        self.assertEqual(names, [
            "01_create_database.sql",
            "02_cloudtrail_logs_projection.sql", "05_validate_projection.sql",
            "03_cloudtrail_logs_org_projection.sql", "05_validate_org.sql",
            "04_cloudtrail_logs_ymd_manual.sql", "05_validate_ymd.sql"])

    def test_only_filters_variants(self):
        t = trail(account_id="1" * 12, region="us-east-1")
        names = [n for n, _ in rd.render_trail(t, rd.HERE, "d", ["ymd"])]
        self.assertEqual(names, ["01_create_database.sql",
                                 "04_cloudtrail_logs_ymd_manual.sql",
                                 "05_validate_ymd.sql"])

    def test_rendered_sql_has_no_leftover_tokens(self):
        t = trail(account_id="1" * 12, org_id="o-abc1234567", accounts="2" * 12,
                  region="us-east-1", prefix="trails/x")
        for name, sql in rd.render_trail(t, rd.HERE, "d", None):
            for token in rd.KNOWN_PLACEHOLDERS:
                self.assertNotIn(token, sql, "%s still has %s" % (name, token))
            self.assertNotIn("TEMPLATE-ONLY", sql)

    def test_suggested_command_carries_the_partition_style(self):
        t = trail(account_id="1" * 12, region="us-east-1")
        _, sql = rd.render_trail(t, rd.HERE, "d", ["ymd"])[1]
        self.assertIn("--partition-style ymd", sql)
        self.assertIn("--table cloudtrail_logs_ymd", sql)


class ReadCsv(unittest.TestCase):
    def test_unknown_column(self):
        path = write_csv("name,bucket,start_date,widget\na,b-bucket,2025-06-01,x\n")
        with self.assertRaisesRegex(rd.CsvError, "unknown column"):
            rd.read_trails(path, TODAY)

    def test_duplicate_name(self):
        path = write_csv("name,bucket,start_date\na,b-bucket,2025-06-01\n"
                         "a,b-bucket,2025-06-01\n")
        with self.assertRaisesRegex(rd.CsvError, "duplicate name"):
            rd.read_trails(path, TODAY)

    def test_blank_and_comment_rows_skipped(self):
        path = write_csv("name,bucket,start_date\n,,\n#note,b-bucket,2025-06-01\n"
                         "a,b-bucket,2025-06-01\n")
        self.assertEqual([t.name for t in rd.read_trails(path, TODAY)], ["a"])

    def test_errors_are_accumulated(self):
        path = write_csv("name,bucket,start_date\na,b-bucket,nope\n"
                         "b,UPPER,2025-06-01\n")
        with self.assertRaises(rd.CsvError) as ctx:
            rd.read_trails(path, TODAY)
        self.assertEqual(len(str(ctx.exception).splitlines()), 2)

    def test_bom_header_is_tolerated(self):
        path = write_csv("﻿name,bucket,start_date\na,b-bucket,2025-06-01\n")
        self.assertEqual([t.name for t in rd.read_trails(path, TODAY)], ["a"])

    def test_example_csv_parses(self):
        path = write_csv(rd.EXAMPLE_CSV)
        trails = rd.read_trails(path, TODAY)
        self.assertEqual([t.name for t in trails],
                         ["prod-org", "sandbox", "sandbox-ymd"])
        self.assertEqual(trails[0].variants(), ["org"])
        self.assertEqual(trails[1].variants(), ["projection", "ymd"])
        self.assertEqual(trails[2].variants(), ["ymd"])


class Cli(unittest.TestCase):
    def test_render_writes_files(self):
        path = write_csv(rd.EXAMPLE_CSV)
        with tempfile.TemporaryDirectory() as out:
            self.assertEqual(rd.main([path, "--out-dir", out]), 0)
            self.assertTrue(os.path.exists(
                os.path.join(out, "prod-org", "03_cloudtrail_logs_org_projection.sql")))
            # second run must refuse rather than clobber
            self.assertEqual(rd.main([path, "--out-dir", out]), 1)
            self.assertEqual(rd.main([path, "--out-dir", out, "--force"]), 0)

    def test_bad_csv_exits_two(self):
        path = write_csv("name,bucket,start_date\na,b-bucket,nope\n")
        with tempfile.TemporaryDirectory() as out:
            self.assertEqual(rd.main([path, "--out-dir", out]), 2)


@unittest.skipIf(sqlglot is None, "sqlglot not installed")
class ParseCheck(unittest.TestCase):
    def test_rendered_sql_parses_as_athena(self):
        t = trail(account_id="1" * 12, org_id="o-abc1234567", accounts="2" * 12,
                  region="us-east-1", prefix="trails/x", end_date="2025-06-05")
        for name, sql in rd.render_trail(t, rd.HERE, "d", None):
            with self.subTest(name=name):
                sqlglot.parse(sql, read="athena")


if __name__ == "__main__":
    unittest.main()
