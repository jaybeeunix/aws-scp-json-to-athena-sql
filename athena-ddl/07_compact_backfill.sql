-- =========================================================================================
-- Backfill <DATABASE>.<TABLE> from <DATABASE>.<SOURCE_TABLE>, one day per statement.
--
-- Window: <WINDOW_START> .. <WINDOW_END>  (<BACKFILL_DAYS> days)
--
-- One statement per day is the whole trick. The source is partition-projected on
-- account_id x region x timestamp, so an unfiltered query lists the full cross product
-- and never finishes; pinning `timestamp` to a single day cuts that by the number of
-- days in the window and brings each statement back into normal Athena territory.
--
-- Run it with the parallel runner -- serially this is <BACKFILL_DAYS> queries back to back:
--
--     ./run_sql.py --work-group scp-impact --jobs 8 <SELF_PATH>
--
-- --jobs 8 is a reasonable default; Athena's default DML concurrency quota is 20-25, and
-- you want headroom for anything else using the workgroup.
--
-- !! INSERT INTO appends. It is not idempotent, and a failed statement can still have
-- !! written files. Before retrying a day, delete its prefix:
-- !!     aws s3 rm --recursive 's3://<BUCKET>/<PREFIX>/<TABLE>/dt=<WINDOW_START>/'
-- !! run_sql.py stops at the first failure for exactly this reason; with --jobs > 1 it
-- !! reports every day that failed so you know which prefixes to clear.
--
-- The SELECT list is positional. It must match 06_cloudtrail_compact.sql's column order
-- exactly, with the dt partition value last -- INSERT INTO binds by position, so a column
-- added to one file and not the other silently shifts the data rather than erroring.
-- =========================================================================================

<BACKFILL_INSERTS>

-- -----------------------------------------------------------------------------------------
-- RECONCILE: did every day land, and land once?
--
-- Run after the backfill. `compacted` should equal `raw` for every day in the window.
-- Higher means a day was inserted twice (see the idempotency warning above); lower or
-- missing means a day failed or has not run yet. Scans both tables, so it is not cheap --
-- it is the one query where reading the raw table across the whole window is the point.
--
-- If the raw side is too slow to list, drop it and just check that the compacted counts
-- have no zero days and no outliers.
-- -----------------------------------------------------------------------------------------
WITH compacted AS (
    SELECT dt AS day, count(*) AS compacted_events
    FROM <DATABASE>.<TABLE>
    WHERE dt BETWEEN '<WINDOW_START>' AND '<WINDOW_END>'
    GROUP BY 1
),
raw AS (
    SELECT replace("timestamp", '/', '-') AS day, count(*) AS raw_events
    FROM <DATABASE>.<SOURCE_TABLE>
    WHERE <SOURCE_WINDOW_PREDICATE>
    GROUP BY 1
)
SELECT COALESCE(compacted.day, raw.day)                        AS day,
       COALESCE(raw_events, 0)                                 AS raw_events,
       COALESCE(compacted_events, 0)                           AS compacted_events,
       COALESCE(compacted_events, 0) - COALESCE(raw_events, 0) AS difference
FROM compacted
FULL OUTER JOIN raw ON compacted.day = raw.day
WHERE COALESCE(compacted_events, 0) <> COALESCE(raw_events, 0)
ORDER BY 1;
