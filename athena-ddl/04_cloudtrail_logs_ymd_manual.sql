-- =========================================================================================
-- <DATABASE>.<TABLE> -- manual year/month/day partitions
--
-- Use when you cannot use partition projection (e.g. the table is maintained by a Glue
-- crawler, or you only want a few specific days registered).
--
--     ./scp_to_athena.py ... --database <DATABASE> --table <TABLE> --partition-style ymd
--
-- TEMPLATE-ONLY BEGIN
-- `<TOKENS>` are filled in by render_ddl.py from a CSV row. To fill them by hand:
--     <BUCKET>       S3 bucket holding the trail
--     <PREFIX>       key prefix above AWSLogs/, or delete that whole path segment
--     <ACCOUNT_ID>   the account that owns the trail
--     <REGION>       the ONE region this table covers
-- plus one ADD PARTITION entry per day in the window, at the bottom of this file.
-- TEMPLATE-ONLY END
--
-- Partitions are NOT auto-discovered: MSCK REPAIR TABLE does not work here because the
-- S3 path is not Hive-style (no `year=2025/`). Every day must be registered explicitly.
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
    year  STRING,
    month STRING,
    day   STRING
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
LOCATION 's3://<BUCKET>/<PREFIX>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<REGION>/';

-- Register the days in the analysis window. Athena takes many PARTITION clauses per
-- ALTER, so these are batched; run each statement separately in the console.
<ADD_PARTITIONS>

-- Note this table is pinned to ONE region by its LOCATION. For multi-region coverage
-- either add a region partition key (and a region segment to each partition LOCATION),
-- or prefer the projection tables in 02/03 -- which is why those are the default.
