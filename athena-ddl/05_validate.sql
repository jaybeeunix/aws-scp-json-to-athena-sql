-- =========================================================================================
-- Smoke tests for <DATABASE>.<TABLE>. Run these before trusting anything in
-- athena-queries/.
--
--
-- TEMPLATE-ONLY BEGIN
-- `<TOKENS>` are filled in by render_ddl.py from a CSV row. By hand, the two partition
-- filters below become `"timestamp" = '2025/09/01'` style for the projection tables
-- (02/03), or `"year" = '2025' AND "month" = '09' AND ...` for the ymd table (04).
-- TEMPLATE-ONLY END
-- =========================================================================================

-- 1. Does the table read at all, and does the partition filter prune?
--    Should return rows fast and scan a small number of MB.
SELECT eventtime, eventsource, eventname, awsregion, recipientaccountid,
       useridentity.type AS principal_type, useridentity.arn AS principal_arn
FROM <DATABASE>.<TABLE>
WHERE <SAMPLE_DAY_PREDICATE>
LIMIT 10;

-- 2. Do the nested fields the generated queries depend on actually resolve?
--    has_session_issuer should be non-zero -- the generated SQL coalesces it with
--    useridentity.arn to match `aws:PrincipalArn` against role ARNs.
SELECT count(*)                                             AS rows,
       count(useridentity.arn)                              AS has_principal_arn,
       count(useridentity.sessioncontext.sessionissuer.arn) AS has_session_issuer,
       count(tlsdetails)                                    AS has_tls,
       count_if(cardinality(resources) > 0)                 AS has_resources
FROM <DATABASE>.<TABLE>
WHERE <SAMPLE_DAY_PREDICATE>;

-- 3. Which accounts and regions are actually covered by the trail?
--    If an account you care about is missing here, the SCP analysis will
--    silently report zero impact for it. Same for a region missing from the
--    projection enum -- it cannot show up no matter what the trail holds.
SELECT recipientaccountid, awsregion, count(*) AS events
FROM <DATABASE>.<TABLE>
WHERE <SAMPLE_DAY_PREDICATE>
GROUP BY 1, 2
ORDER BY events DESC;

-- 4. Management events only, or data events too?
--    `Data` showing up means s3:GetObject-style denials are visible. If this is
--    all `Management`, SCPs on data-plane actions will look harmless when they are not.
SELECT eventtype, readonly, count(*) AS events
FROM <DATABASE>.<TABLE>
WHERE <SAMPLE_DAY_PREDICATE>
GROUP BY 1, 2
ORDER BY events DESC;

-- 5. Confirm the window the generator was given (<WINDOW_START> .. <WINDOW_END>) has
--    data on both ends. If first_event/last_event sit well inside the window, the
--    trail does not cover it and the impact numbers understate reality.
SELECT min(eventtime) AS first_event, max(eventtime) AS last_event, count(*) AS events
FROM <DATABASE>.<TABLE>
WHERE <WINDOW_PREDICATE>;
