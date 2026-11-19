-- =========================================================================================
-- <DATABASE>.<TABLE> -- MULTI-ACCOUNT bucket, no organization prefix.
--
-- For the common arrangement where N accounts each have their own trail, all pointed
-- at one bucket. The layout is the org one minus the <org-id> path segment:
--
--   org trail     s3://bucket/AWSLogs/o-xxxxxxxxxx/<account-id>/CloudTrail/<region>/...
--   this          s3://bucket/AWSLogs/<account-id>/CloudTrail/<region>/...
--   single acct   s3://bucket/AWSLogs/<account-id>/CloudTrail/<region>/...   (one id only)
--
-- Note the last two are the same shape -- the difference is how many account prefixes
-- are there. That is why this template exists: 02 hardcodes ONE account id in its
-- LOCATION, so pointing it at a bucket holding thirteen covers one of them and silently
-- reports nothing for the other twelve. In an SCP impact report "no rows" reads as
-- "this policy blocks nothing", which is the wrong answer to be confident about.
--
--     ./scp_to_athena.py ... --database <DATABASE> --table <TABLE>
--
-- TEMPLATE-ONLY BEGIN
-- `<TOKENS>` are filled in by render_ddl.py from a CSV row. To fill them by hand:
--     <BUCKET>       S3 bucket the trails deliver to
--     <PREFIX>       key prefix above AWSLogs/, or delete that whole path segment
--     projection.account_id.values comma-separated account IDs, no spaces -- every
--                    account whose prefix is in the bucket, not just the ones you
--                    expect; a missing one returns no rows rather than an error
--     projection.region.values     comma-separated enum, `render_ddl.py --print-regions`
--     projection.timestamp.range   first day the trail has data (yyyy/MM/dd) then ,NOW
-- (`${account_id}` / `${region}` / `${timestamp}` are Athena projection syntax, not tokens.)
-- TEMPLATE-ONLY END
--
-- S3 layout assumed:
--   s3://<BUCKET>/<PREFIX>/AWSLogs/<account-id>/CloudTrail/<region>/yyyy/MM/dd/
-- =========================================================================================

CREATE EXTERNAL TABLE IF NOT EXISTS <DATABASE>.<TABLE> (
    eventversion       STRING,
    -- Change this struct only with a live query to back it up. CloudTrailSerde
    -- reflects over a fixed Java class rather than matching JSON keys by name,
    -- so the declaration has to line up with that class. Verified against a
    -- real trail:
    --   * declaring it STRING to read with json_extract_scalar() fails at read
    --     time -- "GENERIC_INTERNAL_ERROR: class ...ReflectionStructObject
    --     Inspector cannot be cast to ...PrimitiveObjectInspector";
    --   * dropping sub-fields from the MIDDLE shifts everything after them --
    --     "HIVE_BAD_DATA: Error Parsing a column in the table: null";
    --   * webidfederationdata's MAP<STRING, STRING> breaks every read that
    --     touches useridentity, because Trino materialises the whole struct
    --     before projecting one field -- "HIVE_BAD_DATA: ... Current entry
    --     must be closed before a null can be written". It is the last field
    --     of sessioncontext, so dropping it shifts nothing. Hence its absence
    --     below; AWS's canonical DDL still lists it.
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
    requestparameters  STRING,
    responseelements   STRING,
    additionaleventdata STRING,
    requestid          STRING,
    eventid            STRING,
    resources          ARRAY<STRUCT<
        arn:       STRING,
        accountid: STRING,
        type:      STRING>>,
    eventtype          STRING,
    apiversion         STRING,
    readonly           STRING,
    recipientaccountid STRING,
    serviceeventdetails STRING,
    sharedeventid      STRING,
    vpcendpointid      STRING,
    -- 'Management' | 'Data' | 'Insight' | 'NetworkActivity', direct from the
    -- record rather than inferred from eventtype. Absent from the oldest
    -- eventversions, so expect NULLs -- query 2 in 05_validate.sql counts it
    -- per version. Unreadable under the old CloudTrailSerde; see the SerDe
    -- note below.
    eventcategory      STRING,
    -- Must be a STRUCT for the same reason as useridentity above: this SerDe
    -- reflects over a fixed Java class, and declaring an object column STRING
    -- fails at read time with ReflectionStructObjectInspector cannot be cast
    -- to PrimitiveObjectInspector. aws:SecureTransport only needs IS NOT NULL,
    -- which works either way -- but only the STRUCT form actually loads.
    tlsdetails         STRUCT<
        tlsversion:               STRING,
        ciphersuite:              STRING,
        clientprovidedhostheader: STRING>
)
PARTITIONED BY (
    account_id  STRING,
    region      STRING,
    `timestamp` STRING
)
-- The Hive JSON SerDe, per AWS's current documented CloudTrail table. It maps
-- JSON keys to columns BY NAME, so declaring a subset of fields is supported
-- and newer eventversions just contribute fields we ignore.
--
-- The predecessor here was com.amazon.emr.hive.serde.CloudTrailSerde, which
-- reflects over a fixed Java class instead. AWS warns it "does not currently
-- handle some of the newer CloudTrail fields", and against a trail emitting
-- eventversion 1.11 every read touching `useridentity` failed with
-- "HIVE_BAD_DATA: ... Current entry must be closed before a null can be
-- written" -- including after webidfederationdata's MAP was removed.
--
-- With THIS SerDe every object column must be a STRUCT. Declaring one STRING
-- to use json_extract_scalar() yields a bare '{' and blanks every column after
-- it; only requestparameters/responseelements/additionaleventdata are genuine
-- JSON strings in the source record.
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://<BUCKET>/<PREFIX>/AWSLogs/'
TBLPROPERTIES (
    'projection.enabled'                 = 'true',

    'projection.account_id.type'         = 'enum',
    'projection.account_id.values'       = '<ACCOUNT_IDS>',

    -- Defaults to all 34 regions in the `aws` (commercial) partition. GovCloud is
    -- excluded; it is a separate partition and never lands in a commercial trail bucket.
    'projection.region.type'             = 'enum',
    'projection.region.values'           = '<REGIONS>',

    'projection.timestamp.type'          = 'date',
    'projection.timestamp.format'        = 'yyyy/MM/dd',
    'projection.timestamp.interval'      = '1',
    'projection.timestamp.interval.unit' = 'DAYS',
    'projection.timestamp.range'         = '<RANGE_START>,<RANGE_END>',

    'storage.location.template'          = 's3://<BUCKET>/<PREFIX>/AWSLogs/${account_id}/CloudTrail/${region}/${timestamp}'
);

-- Notes
--   * Same accounts x regions x days listing cost as the org table, and the same remedy:
--     past a couple of hundred accounts this stops being queryable and the compacted
--     table in 06 is what you want. render_ddl.py warns with the actual prefix count.
--   * The account enum is what discover.sh read out of the bucket, so it lists accounts
--     that have actually delivered. An account that has a trail configured but has never
--     written is absent, and absent reads as zero rows -- which in an impact report looks
--     like "nothing to worry about here".
--   * Unlike the org table there is no single trail to check: each account owns its own,
--     so one of them being switched off is invisible from this side. Query 3 in
--     05_validate_multi.sql counts events per account for that reason -- an account in
--     the enum with no rows is the thing to chase.
--   * SCPs never apply to the management account. Leave it out of the enum, or pass
--     `--exclude-accounts <mgmt-account-id>` to the generator.
