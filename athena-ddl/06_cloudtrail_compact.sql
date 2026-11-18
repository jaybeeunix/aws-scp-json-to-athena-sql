-- =========================================================================================
-- <DATABASE>.<TABLE> -- COMPACTED Parquet copy of an organization trail.
--
-- This is the table to point the generator at for a large org. It exists because
-- partition projection over an org trail does not scale with member accounts:
--
--     accounts x regions x days = prefixes Athena lists before reading a byte
--     2400 x 34 x 123 = 10,036,800   -- times out during planning, every query
--
-- The fix is to pay that listing cost ONCE, a day at a time (2400 x 34 x 1 = 81,600
-- prefixes, which Athena handles fine), and write the result to a table partitioned by
-- date alone. `account_id` and `region` stop being partition keys and become ordinary
-- columns, so the cross product disappears and every SCP query gets all accounts and
-- all regions for free.
--
-- 07_compact_backfill.sql holds the per-day INSERT INTO statements that fill it.
--
-- TEMPLATE-ONLY BEGIN
-- `<TOKENS>` are filled in by render_ddl.py from a CSV row. To fill them by hand:
--     <BUCKET>       S3 bucket to write the compacted table to -- see the warning below
--     <PREFIX>       key prefix above the table, or delete that whole path segment
--     projection.dt.range  first day to compact (yyyy-MM-dd) then ,NOW
-- (`${dt}` is Athena projection syntax, not a token.)
-- TEMPLATE-ONLY END
--
-- !! The LOCATION must be an empty prefix that nothing else writes to. INSERT INTO
-- !! appends, and DROP TABLE on an external table leaves the files behind. Do not
-- !! point this at the trail bucket's AWSLogs/ tree.
-- =========================================================================================

CREATE EXTERNAL TABLE IF NOT EXISTS <DATABASE>.<TABLE> (
    -- Same column names, types and struct shapes as the raw trail table, so every
    -- query generated against that table runs here unchanged -- only --partition-style
    -- differs. Keep it that way; the point of this table is to be a drop-in.
    eventversion       STRING,
    useridentity       STRUCT<
        type:          STRING,
        principalid:   STRING,
        arn:           STRING,
        accountid:     STRING,
        invokedby:     STRING,
        accesskeyid:   STRING,
        username:      STRING,
        sessioncontext: STRUCT<
            attributes: STRUCT<
                mfaauthenticated: STRING,
                creationdate:     STRING>,
            sessionissuer: STRUCT<
                type:        STRING,
                principalid: STRING,
                arn:         STRING,
                accountid:   STRING,
                username:    STRING>,
            ec2roledelivery: STRING>>,
    eventtime          STRING,
    eventsource        STRING,
    eventname          STRING,
    awsregion          STRING,
    sourceipaddress    STRING,
    useragent          STRING,
    errorcode          STRING,
    errormessage       STRING,
    -- Kept because Resource / NotResource and the aws:RequestTag approximation
    -- string-match against it. It is the largest column here by a wide margin; if the
    -- table is too big, dropping it is the lever, at the cost of those two features.
    requestparameters  STRING,
    eventid            STRING,
    resources          ARRAY<STRUCT<
        arn:       STRING,
        accountid: STRING,
        type:      STRING>>,
    eventtype          STRING,
    readonly           STRING,
    recipientaccountid STRING,
    vpcendpointid      STRING,
    eventcategory      STRING,
    tlsdetails         STRUCT<
        tlsversion:               STRING,
        ciphersuite:              STRING,
        clientprovidedhostheader: STRING>
    -- Deliberately absent, because nothing in scp_to_athena.py reads them and together
    -- they are most of the bytes: responseelements, additionaleventdata, requestid,
    -- apiversion, serviceeventdetails, sharedeventid. Add one back here AND in
    -- 07_compact_backfill.sql's SELECT list if you start needing it; the column order
    -- of the two must match, because INSERT INTO binds by position, not by name.
)
PARTITIONED BY (
    -- STRING, not DATE: the generated predicate is a plain string BETWEEN
    -- ('--partition-style iso'), which needs no cast and cannot be tripped up by
    -- Athena's varchar/date coercion rules. Projection still treats it as a date.
    dt STRING
)
STORED AS PARQUET
LOCATION 's3://<BUCKET>/<PREFIX>/<TABLE>/'
TBLPROPERTIES (
    -- ZSTD over the Parquet default of SNAPPY: ~30% smaller for CloudTrail's very
    -- repetitive JSON-derived strings, and bytes scanned is what Athena bills.
    -- Requires Athena engine v3.
    'parquet.compression'                = 'ZSTD',

    'projection.enabled'                 = 'true',
    'projection.dt.type'                 = 'date',
    'projection.dt.format'               = 'yyyy-MM-dd',
    'projection.dt.interval'             = '1',
    'projection.dt.interval.unit'        = 'DAYS',
    'projection.dt.range'                = '<DT_RANGE_START>,<DT_RANGE_END>',

    'storage.location.template'          = 's3://<BUCKET>/<PREFIX>/<TABLE>/dt=${dt}'
);

-- Notes
--   * Projection means no ALTER TABLE ADD PARTITION and no MSCK REPAIR after a backfill
--     day lands -- the partition is readable as soon as the files exist.
--   * A day with no data yet is a missing prefix, which reads as zero rows rather than
--     an error. So you can query the window while the backfill is still running; just
--     do not mistake a not-yet-compacted day for a quiet one. 07's last statement
--     reconciles day-by-day row counts against the raw table.
--   * INSERT INTO is NOT idempotent. Re-running a day appends a second copy of it.
--     If a day fails partway, delete s3://<BUCKET>/<PREFIX>/<TABLE>/dt=<day>/ before
--     retrying it.
--   * No sort order is imposed on the write. An `ORDER BY eventsource, eventname` in the
--     INSERT would tighten Parquet row-group statistics and let these queries -- almost
--     all of which filter on eventsource -- skip row groups. It also forces the whole
--     day through a single sort, which on an org trail is where the backfill falls over.
--     Worth trying per-day if your days are small; not the default.
