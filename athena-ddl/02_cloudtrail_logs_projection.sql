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
            ec2roledelivery: STRING,
            webidfederationdata: STRUCT<
                federatedprovider: STRING,
                attributes:        MAP<STRING, STRING>>>>,
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
    tlsdetails         STRING
)
PARTITIONED BY (
    region      STRING,
    `timestamp` STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
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
