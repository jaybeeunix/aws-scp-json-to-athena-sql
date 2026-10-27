-- =========================================================================================
-- <DATABASE>.<TABLE> -- ORGANIZATION trail, partition projection
--
-- This is the one you want for SCP impact analysis: an org trail carries every member
-- account, so `recipientaccountid` in the generated queries is meaningful.
--
--     ./scp_to_athena.py ... --database <DATABASE> --table <TABLE>
--
-- TEMPLATE-ONLY BEGIN
-- `<TOKENS>` are filled in by render_ddl.py from a CSV row. To fill them by hand:
--     <BUCKET>       S3 bucket of the org trail
--     <PREFIX>       key prefix above AWSLogs/, or delete that whole path segment
--     <ORG_ID>       o-xxxxxxxxxx
--     projection.account_id.values comma-separated member account IDs, no spaces
--     projection.region.values     comma-separated enum, `render_ddl.py --print-regions`
--     projection.timestamp.range   first day the trail has data (yyyy/MM/dd) then ,NOW
-- (`${account_id}` / `${region}` / `${timestamp}` are Athena projection syntax, not tokens.)
-- TEMPLATE-ONLY END
--
-- S3 layout assumed:
--   s3://<BUCKET>/<PREFIX>/AWSLogs/<ORG_ID>/<account-id>/CloudTrail/<region>/yyyy/MM/dd/
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
LOCATION 's3://<BUCKET>/<PREFIX>/AWSLogs/<ORG_ID>/'
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

    'storage.location.template'          = 's3://<BUCKET>/<PREFIX>/AWSLogs/<ORG_ID>/${account_id}/CloudTrail/${region}/${timestamp}'
);

-- Notes
--   * accounts x regions x days is the number of S3 prefixes Athena probes when nothing
--     but `timestamp` is filtered. With the full region enum that is 50 accounts x
--     34 regions x 100 days = 170k prefixes, which is slow. Two ways to cut it down,
--     both worth doing:
--       - list only the accounts in scope for the SCP in the CSV's `accounts` column
--         (and the same set in `--accounts` so the row filter matches), and
--       - narrow the CSV's `regions` column to regions the org actually uses.
--   * The management account is in the trail but SCPs never apply to it. Leave it out of
--     the enum, or pass `--exclude-accounts <mgmt-account-id>` to the generator.
--   * If the account list changes often, ALTER TABLE SET TBLPROPERTIES the enum rather
--     than recreating the table. There is no projection type that enumerates a prefix.
