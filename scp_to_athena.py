#!/usr/bin/env python3
"""
scp_to_athena.py -- turn AWS Service Control Policy JSON into Athena SQL that
finds CloudTrail events the SCP *would have blocked*.

For each Deny statement in each policy, the script emits:

  * a SUMMARY query  -- one row per (account, principal, service, api, region)
                        with counts, for "what would break if I attach this?"
  * a DETAIL query   -- individual events, for drilling into the summary rows.

Statements are translated element by element:

  Action / NotAction  -> eventsource + eventname predicates
  Resource / NotResource -> resources[].arn (plus a best-effort
                            requestparameters match, since management events
                            frequently leave resources[] empty)
  Condition           -> useridentity / awsregion / sourceipaddress / ... columns

CloudTrail records what happened, not the full IAM request context, so some
condition keys simply cannot be evaluated from logs (aws:ResourceTag/* being the
big one). Rather than silently drop them, the generator leaves the predicate out,
emits `TRUE /* unevaluable */` in its place, and records a CAVEAT in the header
of the query. Those queries therefore OVER-match: treat their output as
"candidates to review", not "confirmed breakage".

Usage
-----
  ./scp_to_athena.py --scp-dir scps \\
      --database cloudtrail --table cloudtrail_logs \\
      --start 2025-06-01 --end 2025-09-09 \\
      --out-dir athena-queries

  ./scp_to_athena.py scps/RHCloudGovnDenyUnapprovedRegions.json --stdout

Python 3.8+, standard library only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# IAM service prefix -> CloudTrail eventsource
#
# Most prefixes map to "<prefix>.amazonaws.com". These are the ones that don't.
# Override or extend with --service-map <file.json>.
# --------------------------------------------------------------------------
SERVICE_EVENTSOURCE_OVERRIDES: Dict[str, List[str]] = {
    "amp": ["aps.amazonaws.com"],
    "aws-portal": ["billingconsole.amazonaws.com"],
    "chime-sdk-meetings": ["chime.amazonaws.com"],
    "cloudwatch": ["monitoring.amazonaws.com"],
    "configservice": ["config.amazonaws.com"],
    "deploy": ["codedeploy.amazonaws.com"],
    # DocumentDB and Neptune are RDS API surfaces; CloudTrail logs them as rds.
    "docdb": ["rds.amazonaws.com"],
    "neptune": ["rds.amazonaws.com"],
    "elasticloadbalancing": ["elasticloadbalancing.amazonaws.com"],
    "emr": ["elasticmapreduce.amazonaws.com"],
    "execute-api": ["apigateway.amazonaws.com"],
    "keyspaces": ["cassandra.amazonaws.com"],
    "lex-models": ["lex.amazonaws.com"],
    "lex-runtime": ["lex.amazonaws.com"],
    "opensearch": ["es.amazonaws.com", "opensearch.amazonaws.com"],
    "pinpoint-email": ["ses.amazonaws.com"],
    "pinpoint-sms-voice": ["sms-voice.amazonaws.com"],
    "pinpoint-sms-voice-v2": ["sms-voice.amazonaws.com"],
    "pricing": ["api.pricing.amazonaws.com"],
    "sms-messaging": ["sms-voice.amazonaws.com"],
    "sso": ["sso.amazonaws.com", "sso-directory.amazonaws.com", "identitystore.amazonaws.com"],
    "stepfunctions": ["states.amazonaws.com"],
    "timestream-query": ["timestream.amazonaws.com"],
    "timestream-write": ["timestream.amazonaws.com"],
    "trustedadvisor": ["trustedadvisor.amazonaws.com", "support.amazonaws.com"],
}

# Services whose interesting actions are CloudTrail *data* events -- invisible
# unless data event logging is turned on for that resource type.
DATA_EVENT_SERVICES = {
    "s3": "S3 object-level (GetObject/PutObject/DeleteObject) calls are data events",
    "dynamodb": "DynamoDB item-level (GetItem/PutItem/Query/Scan) calls are data events",
    "lambda": "lambda:InvokeFunction is a data event",
    "kms": "kms:Decrypt/Encrypt/GenerateDataKey are logged as management events, but "
           "only for customer-initiated calls",
    "sns": "SNS Publish is a data event",
    "sqs": "SQS Send/Receive/DeleteMessage are data events",
}

# --------------------------------------------------------------------------
# Condition key -> CloudTrail column
#
# `expr`   : SQL expression yielding the value of the condition key
# `kind`   : 'string' | 'arn' | 'ip' | 'bool'
# `note`   : optional caveat attached whenever the key is used
# --------------------------------------------------------------------------
CONDITION_KEYS: Dict[str, Dict[str, str]] = {
    "aws:requestedregion": {
        "expr": "awsregion",
        "kind": "string",
    },
    "aws:principalarn": {
        # For an assumed role, aws:PrincipalArn is the *role* ARN, which
        # CloudTrail carries in sessioncontext.sessionissuer.arn -- not in
        # useridentity.arn (that holds the assumed-role session ARN).
        "expr": "COALESCE(useridentity.sessioncontext.sessionissuer.arn, useridentity.arn)",
        "safe": "COALESCE(useridentity.sessioncontext.sessionissuer.arn, "
                "useridentity.arn, '')",
        "kind": "arn",
    },
    "aws:principalaccount": {
        "expr": "COALESCE(useridentity.accountid, recipientaccountid)",
        "safe": "COALESCE(useridentity.accountid, recipientaccountid, '')",
        "kind": "string",
    },
    "aws:principaltype": {
        "expr": "useridentity.type",
        "kind": "string",
        "note": "aws:PrincipalType values (User/AssumedRole/...) do not map 1:1 onto "
                "useridentity.type (IAMUser/AssumedRole/Root/...); check the match.",
    },
    "aws:userid": {
        "expr": "useridentity.principalid",
        "kind": "string",
    },
    "aws:username": {
        "expr": "useridentity.username",
        "kind": "string",
    },
    "aws:sourceip": {
        "expr": "sourceipaddress",
        "kind": "ip",
    },
    "aws:sourcevpce": {
        "expr": "vpcendpointid",
        "kind": "string",
    },
    "aws:useragent": {
        "expr": "useragent",
        "kind": "string",
    },
    "aws:multifactorauthpresent": {
        "expr": "useridentity.sessioncontext.attributes.mfaauthenticated",
        "kind": "bool",
    },
    "aws:viaawsservice": {
        "expr": "CAST(useridentity.invokedby IS NOT NULL AS varchar)",
        "kind": "bool",
    },
    "aws:principalisawsservice": {
        "expr": "CAST(useridentity.type = 'AWSService' AS varchar)",
        "kind": "bool",
    },
    "aws:calledvia": {
        "expr": "useridentity.invokedby",
        "kind": "string",
        "note": "aws:CalledVia is a multi-valued list; useridentity.invokedby holds at "
                "most one service. Approximate.",
    },
    "aws:securetransport": {
        "expr": "CAST(tlsdetails IS NOT NULL AS varchar)",
        "kind": "bool",
        "note": "aws:SecureTransport is approximated by the presence of tlsdetails.",
    },
}

# Keys CloudTrail cannot answer at all. Mapped to the reason, for the caveat text.
UNEVALUABLE_KEYS: Dict[str, str] = {
    "aws:resourcetag/": "CloudTrail does not record the tags of the resource being acted "
                        "on. Cross-reference AWS Config / Resource Explorer to find which "
                        "of these resources actually carry the tag.",
    "aws:principaltag/": "CloudTrail does not record principal session tags.",
    "aws:principalorgid": "CloudTrail does not record the caller's organization ID.",
    "aws:principalorgpaths": "CloudTrail does not record the caller's OU path.",
    "aws:sourceorgid": "CloudTrail does not record the source organization ID.",
    "aws:sourceaccount": "CloudTrail does not record aws:SourceAccount.",
    "aws:sourcearn": "CloudTrail does not record aws:SourceArn.",
    "aws:tokenissuetime": "CloudTrail does not record token issue time.",
    "aws:currenttime": "aws:CurrentTime must be evaluated against the time window instead.",
    "aws:epochtime": "aws:EpochTime must be evaluated against the time window instead.",
}

# Request-context tag keys we can *guess* at by string-matching requestparameters.
REQUEST_TAG_PREFIXES = ("aws:requesttag/", "aws:tagkeys")

SQL_RESERVED = {"timestamp", "date", "year", "month", "day", "region", "table", "values"}


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def as_list(value) -> List[str]:
    """SCP elements are string-or-list of string."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def sql_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def quote_ident(name: str) -> str:
    return '"%s"' % name if name.lower() in SQL_RESERVED else name


def iam_glob_to_like(pattern: str) -> Tuple[str, bool]:
    """IAM glob (* and ?) -> SQL LIKE pattern. Returns (pattern, needs_escape)."""
    out: List[str] = []
    needs_escape = False
    for ch in pattern:
        if ch == "*":
            out.append("%")
        elif ch == "?":
            out.append("_")
        elif ch in ("%", "_", "~"):
            out.append("~" + ch)
            needs_escape = True
        else:
            out.append(ch)
    return "".join(out), needs_escape


def iam_glob_to_regex(pattern: str, anchored: bool = True) -> str:
    """IAM glob -> Java/RE2 regex, case-insensitive."""
    parts: List[str] = []
    for ch in pattern:
        if ch == "*":
            parts.append(".*")
        elif ch == "?":
            parts.append(".")
        else:
            parts.append(re.escape(ch))
    body = "".join(parts)
    return "(?i)" + ("^" + body + "$" if anchored else body)


def match_expr(column: str, pattern: str, negate: bool = False,
               ignore_case: bool = False) -> str:
    """Build `col = 'x'` / `col LIKE 'x%'`, honouring IAM globs."""
    col = "lower(%s)" % column if ignore_case else column
    val = pattern.lower() if ignore_case else pattern

    if "*" not in pattern and "?" not in pattern:
        return "%s %s %s" % (col, "<>" if negate else "=", sql_literal(val))

    like, needs_escape = iam_glob_to_like(val)
    expr = "%s %s %s" % (col, "NOT LIKE" if negate else "LIKE", sql_literal(like))
    if needs_escape:
        expr += " ESCAPE '~'"
    return expr


class Pred(NamedTuple):
    """One WHERE-clause conjunct, optionally preceded by an explanatory comment."""
    sql: str
    comment: Optional[str] = None


def and_join(predicates: Sequence[str], indent: str = "    ") -> str:
    """Join bare predicate strings with AND (used inside nested expressions)."""
    parts = [p for p in predicates if p and p.strip() != "TRUE"]
    if not parts:
        return "TRUE"
    if len(parts) == 1:
        return parts[0]
    sep = "\n%sAND " % indent
    return sep.join(parts)


def render_where(predicates: Sequence[Pred], pad: str = "    ") -> str:
    """
    Render conjuncts as an indented WHERE body.

    Comments always occupy whole lines -- never trailing an `AND` -- so that
    multi-line predicates stay valid SQL.
    """
    lines: List[str] = []
    first = True
    for pred in predicates:
        if not pred.sql or pred.sql.strip() == "TRUE":
            continue
        if pred.comment:
            for comment_line in pred.comment.split("\n"):
                lines.extend(_wrap_comment(comment_line, pad + "-- "))
        body = pred.sql.split("\n")
        lines.append(pad + ("" if first else "AND ") + body[0])
        for continuation in body[1:]:
            lines.append(pad + "    " + continuation)
        first = False
    return "\n".join(lines) if lines else pad + "TRUE"


def or_join(predicates: Sequence[str], width: int = 100) -> str:
    parts = [p for p in predicates if p]
    if not parts:
        return "FALSE"
    if len(parts) == 1:
        return parts[0]
    inline = "(" + " OR ".join(parts) + ")"
    if len(inline) <= width and "\n" not in inline:
        return inline
    return "(\n    " + "\n    OR ".join(parts) + "\n)"


def wrap(expr: str) -> str:
    """Parenthesise unless it is already a single atom."""
    if expr in ("TRUE", "FALSE"):
        return expr
    if expr.startswith("(") and expr.endswith(")"):
        return expr
    return "(" + expr + ")"


def looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return (
        "…" in value                     # the literal … character
        or "..." in value
        or lowered.startswith("your-")
        or "your-organization" in lowered
        or "ourtagname" in lowered
        or "example" in lowered
        or lowered in ("changeme", "todo", "tbd")
    )


# --------------------------------------------------------------------------
# Action / NotAction
# --------------------------------------------------------------------------
class ActionTranslator:
    def __init__(self, service_map: Dict[str, List[str]]):
        self.service_map = service_map

    def event_sources(self, prefix: str) -> List[str]:
        key = prefix.lower()
        if key in self.service_map:
            return list(self.service_map[key])
        return ["%s.amazonaws.com" % key]

    def predicate(self, actions: Sequence[str], caveats: "CaveatBag") -> str:
        """OR of per-service predicates matching the given IAM actions."""
        if not actions:
            return "TRUE"

        by_prefix: Dict[str, List[str]] = {}
        for action in actions:
            if action.strip() == "*":
                return "TRUE"
            if ":" not in action:
                caveats.add("Action %r has no service prefix and was skipped." % action)
                continue
            prefix, verb = action.split(":", 1)
            by_prefix.setdefault(prefix.strip().lower(), []).append(verb.strip())

        # Services taken wholesale ("svc:*") collapse into one IN (...) list.
        whole_services: List[str] = []
        scoped: List[str] = []

        for prefix in sorted(by_prefix):
            verbs = by_prefix[prefix]
            sources = self.event_sources(prefix)

            if prefix in DATA_EVENT_SERVICES:
                caveats.add("%s: %s -- rows will be missing unless the trail logs data "
                            "events for it." % (prefix, DATA_EVENT_SERVICES[prefix]))
            if prefix in self.service_map:
                caveats.add("IAM prefix '%s' maps to eventsource %s (they differ)."
                            % (prefix, ", ".join(sources)))

            if any(v == "*" for v in verbs):
                whole_services.extend(sources)
                continue

            src_pred = (match_expr("eventsource", sources[0]) if len(sources) == 1
                        else "eventsource IN (%s)" % ", ".join(sql_literal(s) for s in sources))

            exact = sorted({v for v in verbs if "*" not in v and "?" not in v})
            globs = sorted({v for v in verbs if "*" in v or "?" in v})

            name_preds: List[str] = []
            if len(exact) == 1:
                name_preds.append(match_expr("eventname", exact[0]))
            elif exact:
                name_preds.append("eventname IN (%s)"
                                  % ", ".join(sql_literal(v) for v in exact))
            for glob in globs:
                name_preds.append(match_expr("eventname", glob))

            scoped.append("(%s AND %s)" % (src_pred, or_join(name_preds)))
            caveats.add_eventname_note()

        clauses: List[str] = []
        if whole_services:
            uniq = sorted(set(whole_services))
            clauses.append("eventsource = %s" % sql_literal(uniq[0]) if len(uniq) == 1
                           else "eventsource IN (\n%s\n)"
                                % ",\n".join("    " + sql_literal(s) for s in uniq))
        clauses.extend(scoped)

        if not clauses:
            return "TRUE"
        if len(clauses) == 1:
            return clauses[0]
        return "(\n    " + "\n    OR ".join(clauses) + "\n)"


# --------------------------------------------------------------------------
# Resource / NotResource
# --------------------------------------------------------------------------
def resource_predicate(resources: Sequence[str], caveats: "CaveatBag") -> str:
    """
    Match SCP Resource ARNs against CloudTrail.

    resources[] is populated for data events and for many management events, but
    plenty of management events leave it empty, so we also do a coarse substring
    match on requestparameters using the literal part of the ARN.
    """
    if not resources or any(r.strip() == "*" for r in resources):
        return "TRUE"

    arn_regexes = [iam_glob_to_regex(r) for r in resources]
    arn_match = or_join([
        "regexp_like(COALESCE(r.arn, ''), %s)" % sql_literal(rx) for rx in arn_regexes
    ])
    clauses = [
        "(resources IS NOT NULL AND cardinality(filter(resources, r -> %s)) > 0)" % arn_match
    ]

    # Coarse fallback: longest literal token from each ARN (bucket name, table
    # name, key id, ...) searched for anywhere in requestparameters.
    tokens = set()
    for res in resources:
        for token in re.split(r"[:/*?]", res):
            token = token.strip()
            if len(token) >= 4 and token not in ("arn", "aws", "amazonaws", "com"):
                tokens.add(token)
    if tokens:
        rp = or_join([
            "regexp_like(COALESCE(requestparameters, ''), %s)"
            % sql_literal("(?i)" + re.escape(t)) for t in sorted(tokens)
        ])
        clauses.append("(%s)" % rp)
        caveats.add("Resource matching falls back to a substring search of "
                    "requestparameters when resources[] is empty; this can produce "
                    "false positives.")

    for res in resources:
        if looks_like_placeholder(res):
            caveats.add("Resource %r looks like an unfilled placeholder -- the query "
                        "will not match anything real until it is replaced." % res)

    return "(\n    " + "\n    OR ".join(clauses) + "\n)"


# --------------------------------------------------------------------------
# Condition
# --------------------------------------------------------------------------
NEGATING_OPERATORS = {
    "stringnotequals", "stringnotequalsignorecase", "stringnotlike",
    "arnnotlike", "arnnotequals", "notipaddress", "numericnotequals",
}
IGNORE_CASE_OPERATORS = {"stringequalsignorecase", "stringnotequalsignorecase"}


def condition_predicate(condition: dict, caveats: "CaveatBag") -> List["Pred"]:
    """
    Translate a Condition block into one conjunct per condition key.

    IAM semantics: operator blocks AND together, keys within a block AND
    together, and multiple values for one key OR together -- except for negating
    operators, where the key must match *none* of the values.
    """
    if not condition:
        return []

    per_key: List[Pred] = []

    for raw_op, mapping in condition.items():
        op = raw_op
        set_qualifier = ""
        for qual in ("ForAllValues:", "ForAnyValue:"):
            if op.startswith(qual):
                set_qualifier = qual
                op = op[len(qual):]
        if_exists = op.lower().endswith("ifexists")
        if if_exists:
            op = op[: -len("IfExists")]
        op_l = op.lower()
        negate = op_l in NEGATING_OPERATORS
        ignore_case = op_l in IGNORE_CASE_OPERATORS

        if set_qualifier:
            caveats.add("Operator %r uses a set qualifier; CloudTrail exposes single "
                        "values, so the translation is approximate." % raw_op)
        if if_exists:
            caveats.add("Operator %r is *IfExists: it also matches when the key is "
                        "absent. The generated predicate does not model that."
                        % raw_op)

        for raw_key, raw_values in (mapping or {}).items():
            key = raw_key.lower()
            values = as_list(raw_values)
            for value in values:
                if isinstance(value, str) and looks_like_placeholder(value):
                    caveats.add("Condition %s = %r looks like an unfilled placeholder."
                                % (raw_key, value))

            pred = _translate_key(op_l, raw_key, key, values, negate, ignore_case,
                                  caveats)
            if pred and pred != "TRUE":
                label = "Condition: %s %s %s" % (
                    raw_op, raw_key, " | ".join(values) if values else "")
                per_key.append(Pred(pred, label.rstrip()))

    return per_key


def _translate_key(op: str, raw_key: str, key: str, values: List[str],
                   negate: bool, ignore_case: bool, caveats: "CaveatBag") -> str:
    # 1. keys CloudTrail flat-out cannot answer
    for prefix, reason in UNEVALUABLE_KEYS.items():
        if key == prefix.rstrip("/") or key.startswith(prefix):
            caveats.add_unevaluable(raw_key, values, op, reason)
            if key.startswith("aws:resourcetag/"):
                tag = "%s=%s" % (raw_key.split("/", 1)[1],
                                 "|".join(values) if values else "*")
                if tag not in caveats.resource_tag_keys:
                    caveats.resource_tag_keys.append(tag)
            return "TRUE /* unevaluable: %s %s %s */" % (
                raw_key, op, ", ".join(values) or "-")

    # 2. request tags -- best effort against requestparameters
    if key.startswith("aws:requesttag/") or key == "aws:tagkeys":
        return _request_tag_predicate(op, raw_key, key, values, caveats)

    # 3. Null operator on a mappable key
    if op == "null":
        spec = CONDITION_KEYS.get(key)
        if not spec:
            caveats.add_unevaluable(raw_key, values, op,
                                    "Null condition on an unmapped key.")
            return "TRUE /* unevaluable: Null %s */" % raw_key
        want_absent = str(values[0]).lower() == "true" if values else True
        return "%s IS %sNULL" % (spec["expr"], "" if want_absent else "NOT ")

    spec = CONDITION_KEYS.get(key)
    if not spec:
        caveats.add_unevaluable(raw_key, values, op,
                                "No CloudTrail column carries this key.")
        return "TRUE /* unevaluable: %s %s %s */" % (raw_key, op, ", ".join(values))

    if spec.get("note"):
        caveats.add(spec["note"])

    raw_column = spec["expr"]
    kind = spec["kind"]
    # NULL-safe: without this, `NOT (null LIKE '...')` evaluates to NULL and the
    # row silently disappears -- exactly the rows an ArnNotLike deny should catch.
    if kind in ("string", "arn", "ip"):
        column = spec.get("safe") or "COALESCE(%s, '')" % raw_column
    else:
        column = raw_column

    # 4. Bool
    if op in ("bool",):
        want = str(values[0]).lower() == "true" if values else True
        if kind == "bool":
            return ("COALESCE(%s, 'false') = %s"
                    % (column, sql_literal("true" if want else "false")))
        return "%s IS %sNULL" % (column, "NOT " if want else "")

    # 5. IP operators
    if op in ("ipaddress", "notipaddress"):
        preds = ["regexp_like(%s, %s)"
                 % (column, sql_literal(_cidr_to_regex(v))) for v in values]
        caveats.add("IpAddress conditions are matched with a prefix regex on "
                    "sourceipaddress; verify CIDR boundaries for non-octet masks.")
        combined = or_join(preds)
        return "NOT %s" % wrap(combined) if negate else combined

    # 6. Numeric / Date -- rare in SCPs, handled loosely
    if op.startswith("numeric") or op.startswith("date"):
        caveats.add_unevaluable(raw_key, values, op,
                                "Numeric/Date operators are not translated.")
        return "TRUE /* unevaluable: %s %s %s */" % (raw_key, op, ", ".join(values))

    # 7. String / Arn comparison
    exact_only = op in ("stringequals", "stringnotequals", "arnequals", "arnnotequals",
                        "stringequalsignorecase", "stringnotequalsignorecase")
    has_glob = any("*" in v or "?" in v for v in values)

    if exact_only and not has_glob and not ignore_case and len(values) > 1:
        lst = ", ".join(sql_literal(v) for v in values)
        return "%s %sIN (%s)" % (column, "NOT " if negate else "", lst)

    preds = [match_expr(column, v, negate=False, ignore_case=ignore_case)
             for v in values]
    combined = or_join(preds)
    # Negated operators are NOT-any (the key must match none of the values).
    return ("NOT %s" % wrap(combined)) if negate else combined


def _request_tag_predicate(op: str, raw_key: str, key: str, values: List[str],
                           caveats: "CaveatBag") -> str:
    """
    aws:RequestTag/<k> and aws:TagKeys against the raw requestparameters JSON.

    Tag shapes differ per service ({"key":..,"value":..} for EC2,
    {"Key":..,"Value":..} for RDS, {"TagKey":..} elsewhere), so this is a
    deliberately loose regex.
    """
    caveats.add("Request-tag conditions (%s) are approximated by regex over the raw "
                "requestparameters JSON. Tag shapes vary per service, so expect both "
                "false positives and false negatives -- spot-check the hits." % raw_key)

    if key == "aws:tagkeys":
        tag_keys = values
    else:
        tag_keys = [raw_key.split("/", 1)[1]]

    for tag_key in tag_keys:
        if looks_like_placeholder(tag_key):
            caveats.add("Tag key %r looks like an unfilled placeholder." % tag_key)

    def key_present(tag_key: str) -> str:
        rx = r'(?i)"(key|tagkey|tagkeys)"\s*:\s*(\[\s*)?"%s"' % re.escape(tag_key)
        return "regexp_like(COALESCE(requestparameters, ''), %s)" % sql_literal(rx)

    if op == "null":
        want_absent = str(values[0]).lower() == "true" if values else True
        preds = [key_present(tk) for tk in tag_keys]
        combined = or_join(preds)
        # Null:true means "tag was NOT supplied" -> deny.
        return "NOT %s" % wrap(combined) if want_absent else combined

    negate = op in NEGATING_OPERATORS
    preds = [key_present(tk) for tk in tag_keys]
    combined = or_join(preds)
    return "NOT %s" % wrap(combined) if negate else combined


def _cidr_to_regex(cidr: str) -> str:
    """Very coarse CIDR -> prefix regex (octet-aligned masks only)."""
    if "/" not in cidr:
        return "(?i)^" + re.escape(cidr) + "$"
    addr, bits = cidr.split("/", 1)
    try:
        bits_i = int(bits)
    except ValueError:
        return "(?i)^" + re.escape(addr) + "$"
    if ":" in addr:  # IPv6 -- fall back to a plain prefix
        return "(?i)^" + re.escape(addr.rstrip(":")) + ".*$"
    octets = addr.split(".")
    keep = bits_i // 8
    if bits_i % 8 or keep == 0:
        return "(?i)^" + re.escape(".".join(octets[: max(keep, 1)])) + r"\..*$"
    if keep >= 4:
        return "(?i)^" + re.escape(addr) + "$"
    return "(?i)^" + re.escape(".".join(octets[:keep])) + r"\..*$"


# --------------------------------------------------------------------------
# caveats
# --------------------------------------------------------------------------
class CaveatBag:
    def __init__(self) -> None:
        self.items: List[str] = []
        self.unevaluable: List[str] = []
        # Set when a condition depends on the tags of the target resource, which
        # CloudTrail never records -- the caller then needs a resource inventory
        # to finish the analysis by hand.
        self.resource_tag_keys: List[str] = []

    def add(self, text: str) -> None:
        if text not in self.items:
            self.items.append(text)

    def add_eventname_note(self) -> None:
        self.add("CloudTrail eventname is not always identical to the IAM action "
                 "(e.g. s3:ListBucket is logged as ListObjects/ListObjectsV2). "
                 "Named-action predicates can under-match.")

    def add_unevaluable(self, key: str, values: List[str], op: str, reason: str) -> None:
        entry = "%s %s %s -- NOT ENFORCED IN QUERY. %s" % (
            key, op, ", ".join(values) if values else "-", reason)
        if entry not in self.unevaluable:
            self.unevaluable.append(entry)

    def render(self, prefix: str = "-- ") -> str:
        lines: List[str] = []
        if self.unevaluable:
            lines.append(prefix + "UNEVALUABLE CONDITIONS (query OVER-matches):")
            for item in self.unevaluable:
                lines.extend(_wrap_comment(item, prefix + "  * "))
        if self.items:
            lines.append(prefix + "NOTES:")
            for item in self.items:
                lines.extend(_wrap_comment(item, prefix + "  * "))
        return "\n".join(lines)


def _wrap_comment(text: str, bullet: str, width: int = 92) -> List[str]:
    """
    Word-wrap `text` under `bullet`. Every produced line re-opens the SQL line
    comment, so continuation lines can never leak into the statement.
    """
    marker = bullet[: bullet.index("--") + 2] if "--" in bullet else "--"
    continuation = marker + " " * (len(bullet) - len(marker))
    lines: List[str] = []
    current = bullet
    for word in text.split():
        if current not in (bullet, continuation) and len(current) + 1 + len(word) > width:
            lines.append(current.rstrip())
            current = continuation + word
        else:
            current += ("" if current in (bullet, continuation) else " ") + word
    if current.strip(" "):
        lines.append(current.rstrip())
    return lines


# --------------------------------------------------------------------------
# query assembly
# --------------------------------------------------------------------------
DETAIL_COLUMNS = """\
    eventtime,
    recipientaccountid                                        AS account_id,
    awsregion                                                 AS region,
    eventsource,
    eventname,
    useridentity.type                                         AS principal_type,
    useridentity.arn                                          AS principal_arn,
    useridentity.sessioncontext.sessionissuer.arn             AS session_issuer_arn,
    useridentity.username                                     AS username,
    useridentity.invokedby                                    AS invoked_by,
    sourceipaddress,
    useragent,
    errorcode,
    errormessage,
    readonly,
    eventcategory,
    eventid,
    resources,
    requestparameters"""

SUMMARY_COLUMNS = """\
    recipientaccountid                                        AS account_id,
    COALESCE(useridentity.sessioncontext.sessionissuer.arn,
             useridentity.arn,
             useridentity.type)                               AS principal,
    eventsource,
    eventname,
    awsregion                                                 AS region,
    count(*)                                                  AS events,
    count_if(errorcode IS NULL)                               AS succeeded,
    count_if(errorcode IS NOT NULL)                           AS failed,
    count(DISTINCT sourceipaddress)                           AS distinct_source_ips,
    min(eventtime)                                            AS first_seen,
    max(eventtime)                                            AS last_seen"""


class QueryBuilder:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.table = "%s.%s" % (args.database, args.table) if args.database else args.table

    # -- scaffolding shared by every query -------------------------------
    def scope_predicates(self) -> List[Pred]:
        a = self.args
        preds: List[Pred] = []

        part = self.partition_predicate()
        if part:
            preds.append(part)

        if a.start:
            preds.append(Pred(
                "from_iso8601_timestamp(eventtime) >= TIMESTAMP '%s 00:00:00'" % a.start))
        if a.end:
            end_exclusive = (dt.date.fromisoformat(a.end)
                             + dt.timedelta(days=1)).isoformat()
            preds.append(Pred(
                "from_iso8601_timestamp(eventtime) <  TIMESTAMP '%s 00:00:00'"
                % end_exclusive))

        if a.accounts:
            preds.append(Pred("recipientaccountid IN (%s)"
                              % ", ".join(sql_literal(x) for x in a.accounts)))
        if a.exclude_accounts:
            preds.append(Pred("recipientaccountid NOT IN (%s)"
                              % ", ".join(sql_literal(x) for x in a.exclude_accounts),
                              "accounts an SCP cannot affect"))

        # SCPs never apply to these, so they are noise in an impact assessment.
        if not a.include_service_principals:
            preds.append(Pred(
                "COALESCE(useridentity.type, '') NOT IN ('AWSService', 'AWSAccount')",
                "SCPs do not apply to AWS service principals or service-linked roles"))
            preds.append(Pred(
                "COALESCE(useridentity.arn, '') NOT LIKE '%:role/aws-service-role/%'"))
            preds.append(Pred("COALESCE(eventtype, '') <> 'AwsServiceEvent'"))

        if a.status == "successful":
            preds.append(Pred("errorcode IS NULL", "successful calls only"))
        elif a.status == "non-denied":
            preds.append(Pred(
                "(errorcode IS NULL\n"
                " OR errorcode NOT IN ('AccessDenied', 'AccessDeniedException',\n"
                "                      'UnauthorizedOperation',\n"
                "                      'Client.UnauthorizedOperation',\n"
                "                      'Forbidden', 'AuthFailure'))",
                "drop calls that were already denied by existing policy"))

        return preds

    def partition_predicate(self) -> Optional[Pred]:
        a = self.args
        if a.partition_style == "none" or not (a.start and a.end):
            return None
        start_slash = a.start.replace("-", "/")
        end_slash = a.end.replace("-", "/")
        note = "partition pruning -- keeps the scan (and the bill) bounded"
        if a.partition_style == "timestamp":
            col = quote_ident(a.partition_column or "timestamp")
            return Pred("%s BETWEEN '%s' AND '%s'" % (col, start_slash, end_slash), note)
        if a.partition_style == "date":
            col = quote_ident(a.partition_column or "partition_date")
            return Pred("%s BETWEEN DATE '%s' AND DATE '%s'" % (col, a.start, a.end), note)
        if a.partition_style == "ymd":
            return Pred(
                "concat(\"year\", '/', lpad(\"month\", 2, '0'), '/', lpad(\"day\", 2, '0'))\n"
                "    BETWEEN '%s' AND '%s'" % (start_slash, end_slash), note)
        return None

    # -- per statement ----------------------------------------------------
    def statement_where(self, statement: dict, caveats: CaveatBag) -> str:
        translator = ActionTranslator(self.args.service_map)
        preds = self.scope_predicates()

        if "Action" in statement:
            sql = translator.predicate(as_list(statement["Action"]), caveats)
            preds.append(Pred(sql, "Action element"))
        elif "NotAction" in statement:
            inner = translator.predicate(as_list(statement["NotAction"]), caveats)
            sql = ("NOT " + wrap(inner)) if inner != "TRUE" else "FALSE"
            preds.append(Pred(sql, "NotAction element: everything EXCEPT the listed actions"))

        if "Resource" in statement:
            sql = resource_predicate(as_list(statement["Resource"]), caveats)
            preds.append(Pred(sql, "Resource element"))
        elif "NotResource" in statement:
            inner = resource_predicate(as_list(statement["NotResource"]), caveats)
            sql = ("NOT " + wrap(inner)) if inner != "TRUE" else "FALSE"
            preds.append(Pred(sql, "NotResource element"))

        preds.extend(condition_predicate(statement.get("Condition") or {}, caveats))

        return render_where(preds)

    def build(self, policy_name: str, sid: str, statement: dict,
              source_file: str) -> Tuple[str, CaveatBag]:
        caveats = CaveatBag()
        where = self.statement_where(statement, caveats)

        header = self.header(policy_name, sid, statement, source_file, caveats)
        chunks = [header]

        if self.args.mode in ("both", "summary"):
            chunks.append(
                "-- ---------------------------------------------------------------\n"
                "-- SUMMARY: who/what would be blocked, aggregated\n"
                "-- ---------------------------------------------------------------\n"
                "SELECT\n"
                "    %s AS scp,\n"
                "    %s AS sid,\n"
                "%s\n"
                "FROM %s\n"
                "WHERE\n%s\n"
                "GROUP BY 1, 2, 3, 4, 5, 6, 7\n"
                "ORDER BY events DESC\n"
                "LIMIT %d;"
                % (sql_literal(policy_name), sql_literal(sid), SUMMARY_COLUMNS,
                   self.table, where, self.args.limit)
            )

        if caveats.resource_tag_keys and self.args.mode in ("both", "summary"):
            chunks.append(
                "-- ---------------------------------------------------------------\n"
                "-- RESOURCE INVENTORY\n"
                "-- This statement keys off %s, which CloudTrail does not record.\n"
                "-- The summary above therefore lists ALL matching activity. Take the\n"
                "-- resource ARNs below and cross-reference them against your tag\n"
                "-- inventory (AWS Config advanced query, or the Resource Groups\n"
                "-- Tagging API) to find which ones actually carry the tag; only those\n"
                "-- rows would really be denied.\n"
                "-- Note: events with an empty resources[] array drop out here.\n"
                "-- ---------------------------------------------------------------\n"
                "SELECT\n"
                "    %s AS scp,\n"
                "    %s AS sid,\n"
                "    recipientaccountid                                        AS account_id,\n"
                "    res.arn                                                   AS resource_arn,\n"
                "    res.type                                                  AS resource_type,\n"
                "    count(*)                                                  AS events,\n"
                "    count(DISTINCT eventname)                                 AS distinct_apis,\n"
                "    count(DISTINCT COALESCE(\n"
                "        useridentity.sessioncontext.sessionissuer.arn,\n"
                "        useridentity.arn))                                    AS distinct_principals,\n"
                "    max(eventtime)                                            AS last_seen\n"
                "FROM %s\n"
                "CROSS JOIN UNNEST(resources) AS t (res)\n"
                "WHERE\n%s\n"
                "GROUP BY 1, 2, 3, 4, 5\n"
                "ORDER BY events DESC\n"
                "LIMIT %d;"
                % (", ".join(caveats.resource_tag_keys),
                   sql_literal(policy_name), sql_literal(sid),
                   self.table, where, self.args.limit)
            )

        if self.args.mode in ("both", "detail"):
            chunks.append(
                "-- ---------------------------------------------------------------\n"
                "-- DETAIL: individual events\n"
                "-- ---------------------------------------------------------------\n"
                "SELECT\n"
                "    %s AS scp,\n"
                "    %s AS sid,\n"
                "%s\n"
                "FROM %s\n"
                "WHERE\n%s\n"
                "ORDER BY eventtime DESC\n"
                "LIMIT %d;"
                % (sql_literal(policy_name), sql_literal(sid), DETAIL_COLUMNS,
                   self.table, where, self.args.limit)
            )

        return "\n\n".join(chunks) + "\n", caveats

    def summary_select(self, policy_name: str, sid: str, statement: dict) -> Tuple[str, CaveatBag]:
        """Bare SELECT for the combined UNION ALL file."""
        caveats = CaveatBag()
        where = self.statement_where(statement, caveats)
        sql = (
            "SELECT\n"
            "    %s AS scp,\n"
            "    %s AS sid,\n"
            "%s\n"
            "FROM %s\n"
            "WHERE\n%s\n"
            "GROUP BY 1, 2, 3, 4, 5, 6, 7"
            % (sql_literal(policy_name), sql_literal(sid), SUMMARY_COLUMNS,
               self.table, where)
        )
        return sql, caveats

    def header(self, policy_name: str, sid: str, statement: dict,
               source_file: str, caveats: CaveatBag) -> str:
        bar = "-- " + "=" * 89
        lines = [
            bar,
            "-- SCP        : %s" % policy_name,
            "-- Sid        : %s" % sid,
            "-- Source     : %s" % source_file,
            "-- Effect     : %s" % statement.get("Effect", "?"),
        ]
        for element in ("Action", "NotAction", "Resource", "NotResource"):
            if element in statement:
                values = as_list(statement[element])
                shown = ", ".join(values[:6]) + (
                    " ... (+%d more)" % (len(values) - 6) if len(values) > 6 else "")
                lines.append("-- %-10s : %s" % (element, shown))
        if statement.get("Condition"):
            lines.append("-- Condition  : %s"
                         % json.dumps(statement["Condition"], separators=(",", ":")))
        lines.append("--")
        lines.append("-- Rows returned = CloudTrail events this statement WOULD HAVE "
                     "DENIED, assuming")
        lines.append("-- the SCP were attached to the accounts in scope.")
        lines.append("--")
        rendered = caveats.render()
        if rendered:
            lines.append(rendered)
            lines.append("--")
        lines.append("-- Generated %s by scp_to_athena.py" % dt.datetime.now().isoformat(timespec="seconds"))
        lines.append(bar)
        return "\n".join(lines)


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------
def load_policy(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or "Statement" not in data:
        raise ValueError("%s is not an IAM/SCP policy document" % path)
    return data


def collect_inputs(args: argparse.Namespace) -> List[str]:
    paths: List[str] = []
    for item in args.files:
        if os.path.isdir(item):
            paths.extend(sorted(os.path.join(item, f) for f in os.listdir(item)
                                if f.endswith(".json")))
        else:
            paths.append(item)
    if args.scp_dir:
        paths.extend(sorted(os.path.join(args.scp_dir, f)
                            for f in os.listdir(args.scp_dir) if f.endswith(".json")))
    seen, out = set(), []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate Athena queries that find CloudTrail events an SCP "
                    "would block.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage\n-----")[-1],
    )
    parser.add_argument("files", nargs="*", help="SCP JSON files or directories")
    parser.add_argument("--scp-dir", help="directory of SCP JSON files")

    tbl = parser.add_argument_group("Athena table")
    tbl.add_argument("--database", default="default", help="Glue database (default: default)")
    tbl.add_argument("--table", default="cloudtrail_logs", help="CloudTrail table name")
    tbl.add_argument("--partition-style", default="timestamp",
                     choices=["timestamp", "ymd", "date", "none"],
                     help="how the table is partitioned: 'timestamp' string YYYY/MM/dd "
                          "(partition projection, the AWS console default), 'ymd' "
                          "year/month/day columns, 'date' a DATE column, or 'none'")
    tbl.add_argument("--partition-column",
                     help="override the partition column name for 'timestamp'/'date'")

    scope = parser.add_argument_group("scope")
    scope.add_argument("--start", help="inclusive start date, YYYY-MM-DD")
    scope.add_argument("--end", help="inclusive end date, YYYY-MM-DD")
    scope.add_argument("--days", type=int,
                       help="shorthand: last N days ending today (sets --start/--end)")
    scope.add_argument("--accounts", nargs="*", default=[],
                       help="restrict to these recipientaccountid values")
    scope.add_argument("--exclude-accounts", nargs="*", default=[],
                       help="skip these accounts (e.g. the management account, which "
                            "SCPs never affect)")
    scope.add_argument("--status", default="non-denied",
                       choices=["all", "successful", "non-denied"],
                       help="'non-denied' (default) drops calls that already failed "
                            "with an access-denied error; 'successful' keeps only "
                            "errorcode IS NULL")
    scope.add_argument("--include-service-principals", action="store_true",
                       help="keep AWS service principals and service-linked roles "
                            "(SCPs do not apply to them, so they are excluded by default)")

    out = parser.add_argument_group("output")
    out.add_argument("--out-dir", default="athena-queries", help="output directory")
    out.add_argument("--stdout", action="store_true", help="print instead of writing files")
    out.add_argument("--mode", default="both", choices=["both", "summary", "detail"])
    out.add_argument("--limit", type=int, default=500, help="LIMIT for generated queries")
    out.add_argument("--no-combined", action="store_true",
                     help="skip the combined UNION ALL overview query")
    out.add_argument("--service-map", help="JSON file of {iam_prefix: [eventsource, ...]} "
                                           "overrides, merged over the built-ins")

    args = parser.parse_args(argv)

    if not args.files and not args.scp_dir:
        parser.error("give at least one SCP file/directory, or --scp-dir")

    if args.days:
        today = dt.date.today()
        args.start = (today - dt.timedelta(days=args.days)).isoformat()
        args.end = today.isoformat()
    for field in ("start", "end"):
        value = getattr(args, field)
        if value:
            try:
                dt.date.fromisoformat(value)
            except ValueError:
                parser.error("--%s must be YYYY-MM-DD" % field)
    if bool(args.start) != bool(args.end):
        parser.error("--start and --end must be given together (or use --days)")

    service_map = dict(SERVICE_EVENTSOURCE_OVERRIDES)
    if args.service_map:
        with open(args.service_map, "r", encoding="utf-8") as handle:
            for key, value in json.load(handle).items():
                service_map[key.lower()] = as_list(value)
    args.service_map = service_map
    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    builder = QueryBuilder(args)
    paths = collect_inputs(args)
    if not paths:
        print("no SCP JSON files found", file=sys.stderr)
        return 1

    if not args.stdout:
        os.makedirs(args.out_dir, exist_ok=True)

    combined_selects: List[str] = []
    all_caveats: List[Tuple[str, CaveatBag]] = []
    written = 0
    skipped: List[str] = []

    for path in paths:
        try:
            policy = load_policy(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print("skipping %s: %s" % (path, exc), file=sys.stderr)
            skipped.append(path)
            continue

        policy_name = os.path.splitext(os.path.basename(path))[0]
        statements = policy["Statement"]
        if isinstance(statements, dict):
            statements = [statements]

        blocks: List[str] = []
        for index, statement in enumerate(statements):
            if str(statement.get("Effect", "")).lower() != "deny":
                # Allow statements in an SCP widen permissions; they block nothing
                # on their own, so there is nothing to hunt for in CloudTrail.
                continue
            sid = statement.get("Sid") or "%s#%d" % (policy_name, index)
            sql, caveats = builder.build(policy_name, sid, statement, path)
            blocks.append(sql)
            all_caveats.append(("%s / %s" % (policy_name, sid), caveats))

            if not args.no_combined:
                select, _ = builder.summary_select(policy_name, sid, statement)
                combined_selects.append(select)

        if not blocks:
            print("note: %s has no Deny statements, nothing generated" % path,
                  file=sys.stderr)
            continue

        body = "\n\n".join(blocks)
        if args.stdout:
            print(body)
        else:
            dest = os.path.join(args.out_dir, policy_name + ".sql")
            with open(dest, "w", encoding="utf-8") as handle:
                handle.write(body)
            written += 1

    if combined_selects and not args.stdout and not args.no_combined:
        combined = (
            "-- " + "=" * 89 + "\n"
            "-- COMBINED IMPACT OVERVIEW\n"
            "-- One row per (scp, sid, account, principal, service, api, region) across\n"
            "-- every Deny statement. Start here, then open the per-SCP file for detail.\n"
            "-- Read the CAVEATS in each per-SCP file before acting on these numbers.\n"
            "-- " + "=" * 89 + "\n\n"
            + "\nUNION ALL\n".join(combined_selects)
            + "\nORDER BY events DESC\nLIMIT %d;\n" % args.limit
        )
        dest = os.path.join(args.out_dir, "00_combined_impact.sql")
        with open(dest, "w", encoding="utf-8") as handle:
            handle.write(combined)
        written += 1

    if not args.stdout:
        print("wrote %d file(s) to %s/" % (written, args.out_dir))
        flagged = [(name, bag) for name, bag in all_caveats if bag.unevaluable]
        if flagged:
            print("\n%d statement(s) contain conditions CloudTrail cannot evaluate; "
                  "those queries over-match:" % len(flagged))
            for name, bag in flagged:
                print("  %s" % name)
                for item in bag.unevaluable:
                    print("      - %s" % item.split(" -- ")[0])
    return 0 if not skipped else 1


if __name__ == "__main__":
    sys.exit(main())
