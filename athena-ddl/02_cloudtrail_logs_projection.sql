-- =========================================================================================
-- <DATABASE>.<TABLE> -- single-account trail, all regions, partition projection
--
-- Use with the generator's DEFAULT partition style:
--     ./scp_to_athena.py ... --database <DATABASE> --table <TABLE>
--     (equivalent to --partition-style timestamp --partition-column timestamp)
--
-- TEMPLATE-ONLY BEGIN
-- `<TOKENS>` are filled in by render_ddl.py from a CSV row. To fill them by hand:
--     <BUCKET>       S3 bucket holding the trail
--     <PREFIX>       key prefix above AWSLogs/, or delete that whole path segment
--     <ACCOUNT_ID>   the account that owns the trail
--     projection.region.values     comma-separated enum, `render_ddl.py --print-regions`
--     projection.timestamp.range   first day the trail has data (yyyy/MM/dd) then ,NOW
-- (`${region}` / `${timestamp}` below are Athena's own projection syntax, not tokens.)
-- TEMPLATE-ONLY END
--
-- S3 layout assumed:
--   s3://<BUCKET>/<PREFIX>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<region>/yyyy/MM/dd/*.json.gz
--
-- No partition maintenance is needed -- projection resolves partitions at query time.
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
LOCATION 's3://<BUCKET>/<PREFIX>/AWSLogs/<ACCOUNT_ID>/CloudTrail/'
TBLPROPERTIES (
    'projection.enabled'                 = 'true',

    -- Defaults to all 34 regions in the `aws` (commercial) partition. GovCloud is
    -- excluded; it is a separate partition and never lands in a commercial trail bucket.
    'projection.region.type'             = 'enum',
    'projection.region.values'           = '<REGIONS>',

    'projection.timestamp.type'          = 'date',
    'projection.timestamp.format'        = 'yyyy/MM/dd',
    'projection.timestamp.interval'      = '1',
    'projection.timestamp.interval.unit' = 'DAYS',
    'projection.timestamp.range'         = '<RANGE_START>,<RANGE_END>',

    'storage.location.template'          = 's3://<BUCKET>/<PREFIX>/AWSLogs/<ACCOUNT_ID>/CloudTrail/${region}/${timestamp}'
);

-- Notes
--   * `region` must be a partition key because projection templates cannot wildcard a
--     path segment. The generated queries only prune on `timestamp`, so Athena probes
--     every region in the enum for each day in range. Narrow it with the CSV's `regions`
--     column, or add `AND region IN (...)` by hand.
--   * Keep every enabled region in the list, including ones the SCP is meant to deny --
--     those are exactly the rows this analysis is looking for. A region missing from the
--     enum returns no rows, which reads as "the SCP blocks nothing there."
--   * Opt-in regions (af-south-1, ap-east-*, ap-southeast-3..7, eu-central-2, eu-south-*,
--     il-central-1, me-*, mx-central-1, ca-west-1) only have a prefix once enabled, so
--     listing them costs a wasted probe per day but never a wrong answer.
--   * China (cn-north-1, cn-northwest-1) is left out for the same reason as GovCloud --
--     separate partition, separate trail bucket. Set `regions` in the CSV for an aws-cn org.
--   * `projection.timestamp.range` bounds the scan. Starting it years before the trail
--     exists costs listing time on every query.
