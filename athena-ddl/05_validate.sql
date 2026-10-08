-- =========================================================================================
-- Smoke tests. Run these before trusting anything in athena-queries/.
-- Point them at whichever table you created; cloudtrail.cloudtrail_logs below.
-- =========================================================================================

-- 1. Does the table read at all, and does the `timestamp` partition prune?
--    Should return rows fast and scan a small number of MB.
SELECT eventtime, eventsource, eventname, awsregion, recipientaccountid,
       useridentity.type AS principal_type, useridentity.arn AS principal_arn
FROM cloudtrail.cloudtrail_logs
WHERE "timestamp" = '2025/09/01'
LIMIT 10;

-- 2. Do the nested fields the generated queries depend on actually resolve?
--    session_issuer_arn should be non-null for assumed-role events.
SELECT count(*)                                                       AS rows,
       count(useridentity.arn)                                        AS has_principal_arn,
       count(useridentity.sessioncontext.sessionissuer.arn)           AS has_session_issuer,
       count(tlsdetails)                                              AS has_tls,
       count_if(cardinality(resources) > 0)                           AS has_resources
FROM cloudtrail.cloudtrail_logs
WHERE "timestamp" BETWEEN '2025/09/01' AND '2025/09/02';

-- 3. Which accounts and regions are actually covered by the trail?
--    If an account you care about is missing here, the SCP analysis will
--    silently report zero impact for it.
SELECT recipientaccountid, awsregion, count(*) AS events
FROM cloudtrail.cloudtrail_logs
WHERE "timestamp" BETWEEN '2025/09/01' AND '2025/09/02'
GROUP BY 1, 2
ORDER BY events DESC;

-- 4. Management events only, or data events too?
--    `Data` showing up means s3:GetObject-style denials are visible. If this is
--    all `Management`, SCPs on data-plane actions will look harmless when they are not.
SELECT eventtype, readonly, count(*) AS events
FROM cloudtrail.cloudtrail_logs
WHERE "timestamp" BETWEEN '2025/09/01' AND '2025/09/02'
GROUP BY 1, 2
ORDER BY events DESC;

-- 5. Confirm the date window used by the generator has data on both ends.
--    An empty result for either bound means --start/--end are outside the trail.
SELECT min(eventtime) AS first_event, max(eventtime) AS last_event, count(*) AS events
FROM cloudtrail.cloudtrail_logs
WHERE "timestamp" BETWEEN '2025/06/01' AND '2025/09/09';
