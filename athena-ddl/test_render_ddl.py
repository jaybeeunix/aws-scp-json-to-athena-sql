#!/usr/bin/env python3
"""Tests for render_ddl.py.

  cd athena-ddl && python3 -m unittest test_render_ddl

If sqlglot is installed the rendered SQL is also parse-checked against the
Athena dialect; those tests skip otherwise.
"""

from __future__ import annotations

import datetime as dt
import os
import re
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
                         ["prod-org", "big-org", "sandbox", "sandbox-ymd"])
        self.assertEqual(trails[0].variants(), ["org"])
        self.assertEqual(trails[1].variants(), ["org", "compact"])
        self.assertEqual(trails[2].variants(), ["projection", "ymd"])
        self.assertEqual(trails[3].variants(), ["ymd"])


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
def compact_trail(**kwargs) -> rd.Trail:
    row = {"org_id": "o-abc1234567", "accounts": "2" * 12,
           "compact_location": "s3://staging/compact", "end_date": "2025-06-03"}
    row.update(kwargs)
    return trail(**row)


class Compact(unittest.TestCase):
    def test_needs_a_location_and_a_source(self):
        self.assertEqual(trail(org_id="o-abc1234567",
                               accounts="2" * 12).missing_for("compact"),
                         ["compact_location"])
        self.assertEqual(
            trail(compact_location="s3://x-bucket/c").missing_for("compact"),
            ["compact_source"])
        self.assertEqual(compact_trail().missing_for("compact"), [])

    def test_source_prefers_the_org_table(self):
        self.assertEqual(compact_trail().compact_source, "org")
        self.assertEqual(
            trail(account_id="1" * 12,
                  compact_location="s3://x-bucket/c").compact_source, "projection")

    def test_s3_cell_is_split_into_bucket_and_prefix(self):
        t = compact_trail(compact_location="s3://my-bucket/a/b/")
        self.assertEqual((t.compact_bucket, t.compact_prefix), ("my-bucket", "a/b"))
        t = compact_trail(compact_location="s3://my-bucket")
        self.assertEqual((t.compact_bucket, t.compact_prefix), ("my-bucket", ""))

    def test_bad_s3_cell_is_rejected(self):
        with self.assertRaises(rd.CsvError):
            compact_trail(compact_location="/not/an/s3/url")

    def test_overlapping_location_warns(self):
        warnings = compact_trail(bucket="b-bucket",
                                 compact_location="s3://b-bucket/x").warnings()
        self.assertTrue(any("overlaps the trail" in w for w in warnings), warnings)

    def test_many_accounts_without_compaction_warns(self):
        many = " ".join("%012d" % n for n in range(rd.ACCOUNTS_NEEDING_COMPACTION + 1))
        warnings = trail(org_id="o-abc1234567", accounts=many).warnings()
        self.assertTrue(any("compact_location" in w for w in warnings), warnings)
        # ...and goes away once they have set one.
        self.assertFalse(any("compact_location" in w for w in
                             compact_trail(accounts=many).warnings()))

    def test_compact_without_its_source_style_warns(self):
        warnings = compact_trail(styles="compact").warnings()
        self.assertTrue(any("reads from" in w for w in warnings), warnings)
        self.assertFalse(any("reads from" in w for w in
                             compact_trail(styles="org compact").warnings()))

    def test_one_insert_per_day_pinned_to_one_partition(self):
        sql = rd.backfill_sql("db.tgt", "db.src", "timestamp",
                              dt.date(2025, 6, 1), dt.date(2025, 6, 3))
        self.assertEqual(sql.count("INSERT INTO db.tgt"), 3)
        for day in ("2025/06/01", "2025/06/02", "2025/06/03"):
            self.assertIn("WHERE \"timestamp\" = '%s'" % day, sql)
        for day in ("2025-06-01", "2025-06-02", "2025-06-03"):
            self.assertIn("'%s' AS dt" % day, sql)

    def test_backfill_select_matches_the_table_column_order(self):
        """INSERT INTO binds by position. If 06's column list and COMPACT_COLUMNS
        drift apart the data lands in the wrong columns without an error, so pin
        the two together here rather than trusting the comment in each file."""
        text = rd.load_template(rd.HERE, rd.VARIANTS["compact"][0])
        body = text.split("CREATE EXTERNAL TABLE", 1)[1].split("PARTITIONED BY", 1)[0]
        declared = []
        depth = 0
        for raw in body.split("\n"):
            line = raw.strip()
            if not line or line.startswith("--"):
                continue
            if depth == 0 and re.match(r"^[a-z_]+\s+(STRING|STRUCT|ARRAY)", line):
                declared.append(line.split()[0])
            depth += line.count("<") - line.count(">")
        self.assertEqual(tuple(declared), rd.COMPACT_COLUMNS)

    def test_predicates_use_the_dt_column(self):
        self.assertEqual(rd.day_predicate("iso", dt.date(2025, 6, 1)),
                         "dt = '2025-06-01'")
        self.assertEqual(
            rd.window_predicate("iso", dt.date(2025, 6, 1), dt.date(2025, 6, 3)),
            "dt BETWEEN '2025-06-01' AND '2025-06-03'")

    def test_reconcile_compares_each_table_in_its_own_partition_column(self):
        files = dict(rd.render_trail(compact_trail(), rd.HERE, "d", ["compact"]))
        sql = files[rd.BACKFILL_TEMPLATE]
        self.assertIn("WHERE dt BETWEEN '2025-06-01' AND '2025-06-03'", sql)
        self.assertIn("WHERE \"timestamp\" BETWEEN '2025/06/01' AND '2025/06/03'", sql)

    def test_compacted_table_is_written_to_its_own_location(self):
        files = dict(rd.render_trail(
            compact_trail(bucket="trail-bucket",
                          compact_location="s3://staging/compact"),
            rd.HERE, "d", ["compact"]))
        sql = files[rd.VARIANTS["compact"][0]]
        self.assertIn("LOCATION 's3://staging/compact/cloudtrail_logs_compact/'", sql)
        self.assertNotIn("trail-bucket", sql)

    def test_backfill_rides_along_with_the_variant(self):
        names = [n for n, _ in rd.render_trail(compact_trail(), rd.HERE, "d",
                                               ["compact"])]
        self.assertIn(rd.BACKFILL_TEMPLATE, names)
        self.assertIn("09_validate_compact.sql", names)

    def test_compact_validation_sorts_after_the_backfill(self):
        """run_sql.py globs the directory, so filename order is the dependency
        order. At 05 the compact checks ran before 06 created the table -- and
        even after 06 they would have been checking an empty table, because 07
        is what fills it."""
        names = sorted(n for n, _ in rd.render_trail(compact_trail(), rd.HERE,
                                                     "d", None))
        order = {name: i for i, name in enumerate(names)}
        create = order[rd.VARIANTS["compact"][0]]
        backfill = order[rd.BACKFILL_TEMPLATE]
        validate = order["09_validate_compact.sql"]
        self.assertLess(create, backfill)
        self.assertLess(backfill, validate)

    def test_every_rendered_file_sorts_after_what_it_reads(self):
        """A general guard on the numbering: no file may create or query a table
        earlier in the glob than the file that creates it."""
        trail_ = trail(account_id="1" * 12, org_id="o-abc1234567",
                       accounts="2" * 12, region="us-east-1",
                       end_date="2025-06-03",
                       compact_location="s3://staging/compact",
                       accounts_location="s3://staging/lookups")
        files = sorted(rd.render_trail(trail_, rd.HERE, "d", None))
        created = set()
        for name, sql in files:
            body = "\n".join(line for line in sql.split("\n")
                             if not line.lstrip().startswith("--"))
            for referenced in set(re.findall(r"\bcloudtrail\.[a-z0-9_]+", body)):
                if referenced not in created:
                    self.assertRegex(
                        body,
                        r"CREATE (EXTERNAL )?TABLE IF NOT EXISTS %s\b" % referenced,
                        "%s reads %s before any earlier file creates it"
                        % (name, referenced))
            created.update(re.findall(
                r"CREATE (?:EXTERNAL )?TABLE IF NOT EXISTS (cloudtrail\.[a-z0-9_]+)",
                body))


class MultiAccount(unittest.TestCase):
    def test_two_or_more_accounts_without_an_org_id(self):
        self.assertTrue(trail(accounts="1" * 12 + " " + "2" * 12).multi_accounts)

    def test_one_account_is_the_single_account_table(self):
        self.assertFalse(trail(accounts="1" * 12).multi_accounts)
        self.assertEqual(trail(accounts="1" * 12).missing_for("multi"),
                         ["multi_accounts"])

    def test_an_org_id_takes_precedence(self):
        """AWSLogs/<org>/<account>/ is a different path, and 03's org table already
        covers it -- rendering both would be two tables over the same data."""
        t = trail(org_id="o-abc1234567", accounts="1" * 12 + " " + "2" * 12)
        self.assertFalse(t.multi_accounts)
        self.assertEqual(t.variants(), ["org"])

    def test_variant_selected_for_a_shared_bucket(self):
        t = trail(accounts="1" * 12 + " " + "2" * 12)
        self.assertEqual(t.variants(), ["multi"])

    def test_location_is_the_awslogs_root_with_account_projected(self):
        """02 hardcodes one account id in its LOCATION; that is the bug this
        variant exists for, so the path must stop at AWSLogs/."""
        t = trail(bucket="shared-bucket", accounts=" ".join(["1" * 12, "2" * 12]))
        files = dict(rd.render_trail(t, rd.HERE, "d", ["multi"]))
        sql = files[rd.VARIANTS["multi"][0]]
        self.assertIn("LOCATION 's3://shared-bucket/AWSLogs/'", sql)
        self.assertIn("AWSLogs/${account_id}/CloudTrail/${region}/${timestamp}", sql)
        self.assertIn("'projection.account_id.values'       = "
                      "'111111111111,222222222222'", sql)
        # No account id may appear in the LOCATION itself.
        location = [l for l in sql.split("\n") if l.startswith("LOCATION ")][0]
        self.assertNotRegex(location, r"\d{12}")

    def test_prefix_is_honoured(self):
        t = trail(bucket="shared-bucket", prefix="logs/x",
                  accounts=" ".join(["1" * 12, "2" * 12]))
        files = dict(rd.render_trail(t, rd.HERE, "d", ["multi"]))
        self.assertIn("LOCATION 's3://shared-bucket/logs/x/AWSLogs/'",
                      files[rd.VARIANTS["multi"][0]])

    def test_columns_match_the_org_table(self):
        """The two templates duplicate the column block. They have to stay
        identical or a query written against one breaks against the other."""
        def columns(name):
            text = rd.load_template(rd.HERE, name)
            body = text.split("CREATE EXTERNAL TABLE", 1)[1].split("PARTITIONED BY", 1)[0]
            return [line.strip().split()[0] for line in body.split("\n")
                    if re.match(r"^\s{4}[a-z_]+\s+(STRING|STRUCT|ARRAY)", line)]
        self.assertEqual(columns(rd.VARIANTS["multi"][0]),
                         columns(rd.VARIANTS["org"][0]))

    def test_pinned_account_id_is_flagged(self):
        warnings = trail(account_id="1" * 12,
                         accounts=" ".join(["1" * 12, "2" * 12])).warnings()
        self.assertTrue(any("covers only that one" in w for w in warnings), warnings)

    def test_compaction_reads_the_multi_table(self):
        t = trail(accounts=" ".join(["1" * 12, "2" * 12]),
                  compact_location="s3://staging/compact", end_date="2025-06-02")
        self.assertEqual(t.compact_source, "multi")
        files = dict(rd.render_trail(t, rd.HERE, "d", None))
        self.assertIn("FROM cloudtrail.cloudtrail_logs_multi",
                      files[rd.BACKFILL_TEMPLATE])


class OrgAccounts(unittest.TestCase):
    def test_rendered_only_when_a_location_is_given(self):
        names = [n for n, _ in rd.render_trail(trail(account_id="1" * 12),
                                               rd.HERE, "d", None)]
        self.assertNotIn(rd.ACCOUNTS_TEMPLATE, names)
        names = [n for n, _ in rd.render_trail(
            trail(account_id="1" * 12, accounts_location="s3://staging/lookups"),
            rd.HERE, "d", None)]
        self.assertIn(rd.ACCOUNTS_TEMPLATE, names)

    def test_reads_its_own_prefix_not_the_trail_bucket(self):
        files = dict(rd.render_trail(
            trail(account_id="1" * 12, bucket="trail-bucket",
                  accounts_location="s3://staging/lookups", accounts_table="accts"),
            rd.HERE, "d", ["projection"]))
        sql = files[rd.ACCOUNTS_TEMPLATE]
        self.assertIn("LOCATION 's3://staging/lookups/org_accounts/'", sql)
        self.assertIn("cloudtrail.accts", sql)
        self.assertNotIn("trail-bucket", sql)

    def test_suggested_command_passes_the_table_through(self):
        lines = rd.suggested_command(
            trail(account_id="1" * 12, accounts_location="s3://staging/lookups"),
            "projection", "tbl")
        self.assertTrue(any("--accounts-table cloudtrail.org_accounts" in line
                            for line in lines), lines)


class SuggestedCommand(unittest.TestCase):
    def test_every_header_line_is_commented(self):
        """wrap_accounts() returns one entry with embedded newlines. A continuation
        that does not get the `--` prefix is raw SQL inside the header block, which
        makes the whole rendered file unparseable."""
        many = " ".join("%012d" % n for n in range(rd.MAX_SUGGESTED_ACCOUNTS))
        text = rd.header(trail(org_id="o-abc1234567", accounts=many),
                         "03.sql", "d", "org", "tbl")
        for line in text.split("\n"):
            if line.strip():
                self.assertTrue(line.startswith("--"), line)

    def test_small_account_list_is_spelled_out(self):
        lines = rd.suggested_command(
            trail(org_id="o-abc1234567", accounts="1" * 12 + " " + "2" * 12),
            "org", "tbl")
        self.assertTrue(any("--accounts 111111111111 222222222222" in line
                            for line in lines), lines)

    def test_large_account_list_is_replaced_by_advice(self):
        many = " ".join("%012d" % n for n in range(rd.MAX_SUGGESTED_ACCOUNTS + 1))
        lines = rd.suggested_command(
            trail(org_id="o-abc1234567", accounts=many), "org", "tbl")
        self.assertFalse(any(line.strip().startswith("--accounts ")
                             for line in lines), lines)
        self.assertTrue(any("accounts in scope" in line for line in lines), lines)
        # The advice must not land between a `\` continuation and the next flag,
        # or the suggested command stops being runnable when pasted.
        continued = [i for i, line in enumerate(lines) if line.endswith("\\")]
        for i in continued:
            self.assertFalse(lines[i + 1].lstrip().startswith("#"), lines)


class ParseCheck(unittest.TestCase):
    def test_rendered_sql_parses_as_athena(self):
        t = trail(account_id="1" * 12, org_id="o-abc1234567", accounts="2" * 12,
                  region="us-east-1", prefix="trails/x", end_date="2025-06-05")
        for name, sql in rd.render_trail(t, rd.HERE, "d", None):
            with self.subTest(name=name):
                sqlglot.parse(sql, read="athena")

    def test_compact_sql_parses_as_athena(self):
        for name, sql in rd.render_trail(compact_trail(), rd.HERE, "d", None):
            with self.subTest(name=name):
                sqlglot.parse(sql, read="athena")

    def test_org_accounts_sql_parses_as_athena(self):
        t = trail(account_id="1" * 12, accounts_location="s3://staging/lookups")
        files = dict(rd.render_trail(t, rd.HERE, "d", ["projection"]))
        sqlglot.parse(files[rd.ACCOUNTS_TEMPLATE], read="athena")


if __name__ == "__main__":
    unittest.main()
