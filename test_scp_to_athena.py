#!/usr/bin/env python3
"""
Tests for scp_to_athena.py -- run with `python3 -m unittest test_scp_to_athena`
or just `./test_scp_to_athena.py`.

If sqlglot is installed the generated SQL is also parse-checked; otherwise those
assertions are skipped.
"""

import json
import os
import tempfile
import unittest

import scp_to_athena as s2a

try:
    import sqlglot
except ImportError:  # optional
    sqlglot = None


def build(statement, **overrides):
    """Render the WHERE body for a single Deny statement."""
    argv = ["dummy.json", "--database", "ct", "--table", "logs",
            "--start", "2025-01-01", "--end", "2025-01-31"]
    for key, value in overrides.items():
        argv.append("--" + key.replace("_", "-"))
        if value is not True:
            argv.extend(value if isinstance(value, list) else [str(value)])
    args = s2a.parse_args(argv)
    builder = s2a.QueryBuilder(args)
    caveats = s2a.CaveatBag()
    return builder.statement_where(statement, caveats), caveats


def full_sql(policy: dict, name="Test", **overrides):
    argv = ["dummy.json", "--database", "ct", "--table", "logs",
            "--start", "2025-01-01", "--end", "2025-01-31"]
    for key, value in overrides.items():
        argv.append("--" + key.replace("_", "-"))
        if value is not True:
            argv.extend(value if isinstance(value, list) else [str(value)])
    args = s2a.parse_args(argv)
    builder = s2a.QueryBuilder(args)
    sql, _ = builder.build(name, policy["Statement"][0].get("Sid", "s0"),
                           policy["Statement"][0], "dummy.json")
    return sql


class GlobTranslation(unittest.TestCase):
    def test_star_becomes_percent(self):
        self.assertEqual(s2a.iam_glob_to_like("arn:aws:iam::*:root"),
                         ("arn:aws:iam::%:root", False))

    def test_question_mark_becomes_underscore(self):
        self.assertEqual(s2a.iam_glob_to_like("foo?")[0], "foo_")

    def test_literal_wildcards_are_escaped(self):
        pattern, needs_escape = s2a.iam_glob_to_like("100%_off")
        self.assertTrue(needs_escape)
        self.assertEqual(pattern, "100~%~_off")

    def test_escape_clause_is_emitted(self):
        expr = s2a.match_expr("col", "a%b*")
        self.assertIn("ESCAPE '~'", expr)

    def test_no_glob_uses_equality(self):
        self.assertEqual(s2a.match_expr("eventname", "RunInstances"),
                         "eventname = 'RunInstances'")

    def test_regex_is_anchored_and_case_insensitive(self):
        rx = s2a.iam_glob_to_regex("arn:aws:s3:::bucket/*")
        self.assertTrue(rx.startswith("(?i)^"))
        self.assertTrue(rx.endswith("$"))
        self.assertIn(".*", rx)

    def test_sql_literal_escapes_quotes(self):
        self.assertEqual(s2a.sql_literal("it's"), "'it''s'")


class ActionTranslation(unittest.TestCase):
    def setUp(self):
        self.tr = s2a.ActionTranslator(s2a.SERVICE_EVENTSOURCE_OVERRIDES)
        self.caveats = s2a.CaveatBag()

    def test_service_wildcard_matches_eventsource_only(self):
        sql = self.tr.predicate(["s3:*"], self.caveats)
        self.assertEqual(sql, "eventsource = 's3.amazonaws.com'")
        self.assertNotIn("eventname", sql)

    def test_named_actions_collapse_into_in_list(self):
        sql = self.tr.predicate(["ec2:RunInstances", "ec2:CreateVolume"], self.caveats)
        self.assertIn("eventsource = 'ec2.amazonaws.com'", sql)
        self.assertIn("eventname IN ('CreateVolume', 'RunInstances')", sql)

    def test_action_star_matches_everything(self):
        self.assertEqual(self.tr.predicate(["*"], self.caveats), "TRUE")

    def test_wildcard_verb_uses_like(self):
        sql = self.tr.predicate(["s3:Put*"], self.caveats)
        self.assertIn("eventname LIKE 'Put%'", sql)

    def test_known_prefix_mismatch_is_remapped(self):
        # cloudwatch:* is logged under monitoring.amazonaws.com, not cloudwatch.*
        sql = self.tr.predicate(["cloudwatch:*"], self.caveats)
        self.assertIn("monitoring.amazonaws.com", sql)
        self.assertNotIn("cloudwatch.amazonaws.com", sql)
        self.assertTrue(any("cloudwatch" in c for c in self.caveats.items))

    def test_prefix_with_multiple_sources(self):
        sql = self.tr.predicate(["opensearch:*"], self.caveats)
        self.assertIn("es.amazonaws.com", sql)
        self.assertIn("opensearch.amazonaws.com", sql)

    def test_data_event_services_raise_a_caveat(self):
        self.tr.predicate(["s3:GetObject"], self.caveats)
        self.assertTrue(any("data event" in c for c in self.caveats.items))

    def test_notaction_is_negated(self):
        where, _ = build({"Effect": "Deny", "NotAction": ["ec2:DescribeRegions"],
                          "Resource": "*"})
        self.assertIn("NotAction element", where)
        self.assertIn("AND NOT (", where)
        self.assertIn("'ec2.amazonaws.com'", where)


class ConditionTranslation(unittest.TestCase):
    def test_requested_region_not_equals(self):
        where, _ = build({
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"StringNotEquals": {
                "aws:RequestedRegion": ["us-east-1", "us-west-2"]}},
        })
        self.assertIn("awsregion, '') NOT IN ('us-east-1', 'us-west-2')", where)

    def test_requested_region_equals(self):
        where, _ = build({
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}},
        })
        self.assertIn("= 'eu-west-1'", where)
        self.assertNotIn("NOT IN", where.split("Condition:")[-1])

    def test_principal_arn_prefers_session_issuer(self):
        where, _ = build({
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"StringLike": {
                "aws:PrincipalArn": "arn:aws:iam::*:root"}},
        })
        self.assertIn("useridentity.sessioncontext.sessionissuer.arn", where)
        self.assertIn("LIKE 'arn:aws:iam::%:root'", where)

    def test_negated_arn_match_is_null_safe(self):
        # Without COALESCE, `NOT (NULL LIKE ...)` is NULL and the row vanishes.
        where, _ = build({
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"ArnNotLike": {
                "aws:PrincipalArn": ["arn:aws:iam::*:role/Break*"]}},
        })
        self.assertIn("AND NOT (", where)
        self.assertIn("useridentity.arn, '')", where)

    def test_multiple_condition_keys_are_separate_conjuncts(self):
        where, _ = build({
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {
                "StringNotEquals": {"aws:RequestedRegion": ["us-east-1"]},
                "ArnNotLike": {"aws:PrincipalArn": ["arn:aws:iam::*:role/X"]},
            },
        })
        self.assertEqual(where.count("-- Condition:"), 2)

    def test_resource_tag_triggers_an_inventory_query(self):
        sql = full_sql({"Statement": [{
            "Sid": "Prod", "Effect": "Deny", "Action": ["s3:*"], "Resource": "*",
            "Condition": {"StringEquals": {"aws:ResourceTag/environment": ["prod"]}},
        }]})
        self.assertIn("RESOURCE INVENTORY", sql)
        self.assertIn("CROSS JOIN UNNEST(resources)", sql)
        self.assertIn("environment=prod", sql)

    def test_no_inventory_query_without_resource_tags(self):
        sql = full_sql({"Statement": [{
            "Sid": "Plain", "Effect": "Deny", "Action": ["s3:*"], "Resource": "*"}]})
        self.assertNotIn("RESOURCE INVENTORY", sql)

    def test_resource_tag_is_reported_unevaluable(self):
        where, caveats = build({
            "Effect": "Deny", "Action": ["s3:*"], "Resource": "*",
            "Condition": {"StringEquals": {"aws:ResourceTag/environment": ["prod"]}},
        })
        self.assertTrue(caveats.unevaluable)
        self.assertIn("aws:ResourceTag/environment", caveats.unevaluable[0])
        # The predicate must not silently constrain the query.
        self.assertIn("unevaluable", where)

    def test_null_request_tag_means_tag_absent(self):
        where, _ = build({
            "Effect": "Deny", "Action": ["s3:CreateBucket"], "Resource": "*",
            "Condition": {"Null": {"aws:RequestTag/Owner": "true"}},
        })
        self.assertIn("AND NOT (regexp_like(COALESCE(requestparameters", where)
        self.assertIn('"Owner"', where)

    def test_null_request_tag_false_means_tag_present(self):
        where, _ = build({
            "Effect": "Deny", "Action": ["s3:CreateBucket"], "Resource": "*",
            "Condition": {"Null": {"aws:RequestTag/Owner": "false"}},
        })
        condition_part = where.split("-- Condition:")[-1]
        self.assertNotIn("NOT (regexp_like", condition_part)

    def test_mfa_condition(self):
        where, _ = build({
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}},
        })
        self.assertIn("mfaauthenticated", where)

    def test_source_ip(self):
        where, _ = build({
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"NotIpAddress": {"aws:SourceIp": ["10.0.0.0/8"]}},
        })
        self.assertIn("sourceipaddress", where)
        self.assertIn("NOT ", where.split("-- Condition:")[-1])

    def test_unknown_condition_key_is_flagged_not_dropped(self):
        where, caveats = build({
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"StringEquals": {"ec2:InstanceType": "t3.nano"}},
        })
        self.assertTrue(caveats.unevaluable)
        self.assertIn("ec2:InstanceType", caveats.unevaluable[0])

    def test_ifexists_suffix_is_stripped_and_flagged(self):
        where, caveats = build({
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"StringEqualsIfExists": {"aws:RequestedRegion": "ap-south-1"}},
        })
        self.assertIn("awsregion", where)
        self.assertTrue(any("IfExists" in c for c in caveats.items))

    def test_placeholder_values_are_flagged(self):
        _, caveats = build({
            "Effect": "Deny", "Action": ["s3:*"],
            "Resource": ["arn:aws:s3:::your-organization-bucket"],
        })
        self.assertTrue(any("placeholder" in c for c in caveats.items))


class ResourceTranslation(unittest.TestCase):
    def test_star_resource_adds_no_predicate(self):
        where, _ = build({"Effect": "Deny", "Action": ["s3:DeleteBucket"],
                          "Resource": "*"})
        self.assertNotIn("-- Resource element", where)

    def test_specific_arn_matches_resources_array_and_requestparameters(self):
        where, _ = build({
            "Effect": "Deny", "Action": ["s3:DeleteBucket"],
            "Resource": ["arn:aws:s3:::audit-logs", "arn:aws:s3:::audit-logs/*"],
        })
        self.assertIn("filter(resources, r ->", where)
        self.assertIn("cardinality(", where)
        self.assertIn("audit", where)
        self.assertIn("requestparameters", where)

    def test_notresource_is_negated(self):
        where, _ = build({
            "Effect": "Deny", "Action": ["s3:*"],
            "NotResource": ["arn:aws:s3:::allowed-bucket/*"],
        })
        self.assertIn("-- NotResource element", where)
        self.assertIn("AND NOT (", where)


class ScopeOptions(unittest.TestCase):
    def test_partition_styles(self):
        stmt = {"Effect": "Deny", "Action": ["s3:*"], "Resource": "*"}
        self.assertIn('"timestamp" BETWEEN', build(stmt)[0])
        self.assertIn("lpad", build(stmt, partition_style="ymd")[0])
        self.assertIn("DATE '2025-01-01'", build(stmt, partition_style="date")[0])
        self.assertNotIn("partition pruning", build(stmt, partition_style="none")[0])

    def test_custom_partition_column(self):
        where, _ = build({"Effect": "Deny", "Action": ["s3:*"], "Resource": "*"},
                         partition_column="dt")
        self.assertIn("dt BETWEEN '2025/01/01'", where)

    def test_end_date_is_inclusive(self):
        where, _ = build({"Effect": "Deny", "Action": ["s3:*"], "Resource": "*"})
        # --end 2025-01-31 must include all of the 31st
        self.assertIn("TIMESTAMP '2025-02-01 00:00:00'", where)

    def test_service_principals_excluded_by_default(self):
        where, _ = build({"Effect": "Deny", "Action": ["s3:*"], "Resource": "*"})
        self.assertIn("aws-service-role", where)
        self.assertIn("AWSService", where)

    def test_service_principals_can_be_included(self):
        where, _ = build({"Effect": "Deny", "Action": ["s3:*"], "Resource": "*"},
                         include_service_principals=True)
        self.assertNotIn("aws-service-role", where)

    def test_status_filters(self):
        stmt = {"Effect": "Deny", "Action": ["s3:*"], "Resource": "*"}
        self.assertIn("AccessDenied", build(stmt)[0])
        self.assertIn("errorcode IS NULL", build(stmt, status="successful")[0])
        self.assertNotIn("errorcode", build(stmt, status="all")[0])

    def test_account_scoping(self):
        where, _ = build({"Effect": "Deny", "Action": ["s3:*"], "Resource": "*"},
                         accounts=["111122223333"],
                         exclude_accounts=["999988887777"])
        self.assertIn("recipientaccountid IN ('111122223333')", where)
        self.assertIn("recipientaccountid NOT IN ('999988887777')", where)


class CommentSafety(unittest.TestCase):
    def test_every_wrapped_comment_line_reopens_the_comment(self):
        long_text = "word " * 60
        for line in s2a._wrap_comment(long_text, "--   * "):
            self.assertTrue(line.lstrip().startswith("--"),
                            "continuation line is not a comment: %r" % line)

    def test_caveat_render_is_all_comments(self):
        bag = s2a.CaveatBag()
        bag.add("a very long note that will certainly need to wrap " * 4)
        bag.add_unevaluable("aws:ResourceTag/env", ["prod"], "stringequals",
                            "CloudTrail does not record resource tags at all, " * 3)
        for line in bag.render().split("\n"):
            self.assertTrue(line.startswith("--"), "leaked non-comment: %r" % line)

    def test_where_body_comments_are_on_their_own_lines(self):
        where, _ = build({
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"ArnNotLike": {"aws:PrincipalArn": [
                "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*",
                "arn:aws:iam::*:role/AnotherVeryLongRoleNameForWrapping",
                "arn:aws:iam::*:role/YetAnotherLongRoleNameToForceWrapping",
            ]}},
        })
        for line in where.split("\n"):
            stripped = line.strip()
            if "--" in stripped and not stripped.startswith("--"):
                self.fail("inline comment could swallow SQL: %r" % line)


class PolicyHandling(unittest.TestCase):
    def test_allow_statements_generate_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "allow.json")
            with open(path, "w") as handle:
                json.dump({"Version": "2012-10-17", "Statement": [
                    {"Sid": "A", "Effect": "Allow", "Action": "*", "Resource": "*"}]},
                    handle)
            out = os.path.join(tmp, "out")
            s2a.main([path, "--out-dir", out, "--database", "ct", "--table", "logs",
                      "--start", "2025-01-01", "--end", "2025-01-31"])
            self.assertFalse(os.path.exists(os.path.join(out, "allow.sql")))

    def test_single_statement_object_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "one.json")
            with open(path, "w") as handle:
                json.dump({"Version": "2012-10-17", "Statement":
                    {"Sid": "One", "Effect": "Deny", "Action": "iam:*",
                     "Resource": "*"}}, handle)
            out = os.path.join(tmp, "out")
            s2a.main([path, "--out-dir", out, "--database", "ct", "--table", "logs",
                      "--start", "2025-01-01", "--end", "2025-01-31"])
            with open(os.path.join(out, "one.sql")) as handle:
                self.assertIn("iam.amazonaws.com", handle.read())

    def test_service_map_override_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            mapping = os.path.join(tmp, "map.json")
            with open(mapping, "w") as handle:
                json.dump({"widget": ["widget-api.amazonaws.com"]}, handle)
            where, _ = build({"Effect": "Deny", "Action": ["widget:*"],
                              "Resource": "*"}, service_map=mapping)
            self.assertIn("widget-api.amazonaws.com", where)


@unittest.skipIf(sqlglot is None, "sqlglot not installed")
class SqlIsParseable(unittest.TestCase):
    CASES = [
        {"Sid": "Wildcard", "Effect": "Deny", "Action": "*", "Resource": "*"},
        {"Sid": "NotAction", "Effect": "Deny",
         "NotAction": ["s3:*", "ec2:DescribeRegions"], "Resource": "*"},
        {"Sid": "Resources", "Effect": "Deny", "Action": ["s3:DeleteBucket"],
         "Resource": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"]},
        {"Sid": "Conds", "Effect": "Deny", "Action": "*", "Resource": "*",
         "Condition": {
             "StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "us-west-2"]},
             "ArnNotLike": {"aws:PrincipalArn": ["arn:aws:iam::*:role/x*"]},
             "Bool": {"aws:MultiFactorAuthPresent": "false"},
             "Null": {"aws:RequestTag/Owner": "true"},
             "StringEquals": {"aws:ResourceTag/env": "prod"},
             "IpAddress": {"aws:SourceIp": ["10.0.0.0/8"]},
         }},
        {"Sid": "Quotes", "Effect": "Deny", "Action": ["s3:*"],
         "Resource": ["arn:aws:s3:::it's-a-bucket"]},
    ]

    def test_each_case_parses(self):
        for statement in self.CASES:
            with self.subTest(sid=statement["Sid"]):
                sql = full_sql({"Statement": [statement]})
                parsed = [p for p in sqlglot.parse(sql, read="athena") if p]
                # summary + detail, plus a resource inventory when the statement
                # depends on resource tags.
                expected = 3 if "ResourceTag" in json.dumps(statement) else 2
                self.assertEqual(len(parsed), expected)

    def test_repo_policies_parse(self):
        scp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scps")
        if not os.path.isdir(scp_dir):
            self.skipTest("no scps/ directory")
        with tempfile.TemporaryDirectory() as tmp:
            s2a.main(["--scp-dir", scp_dir, "--out-dir", tmp, "--database", "ct",
                      "--table", "logs", "--start", "2025-01-01", "--end", "2025-01-31"])
            files = [f for f in os.listdir(tmp) if f.endswith(".sql")]
            self.assertTrue(files)
            for name in files:
                with self.subTest(file=name):
                    with open(os.path.join(tmp, name)) as handle:
                        sqlglot.parse(handle.read(), read="athena")


if __name__ == "__main__":
    unittest.main(verbosity=2)
