-- =========================================================================================
-- cloudtrail.cloudtrail_logs -- single-account trail, all regions, partition projection
--
-- Use with the generator's DEFAULT partition style:
--     ./scp_to_athena.py ... --database cloudtrail --table cloudtrail_logs
--     (equivalent to --partition-style timestamp --partition-column timestamp)
--
-- Replace before running:
--     <BUCKET>      S3 bucket holding the trail
--     <PREFIX>      trail prefix including the trailing slash, or delete `<PREFIX>/`
--     <ACCOUNT_ID>  the account that owns the trail
--     projection.timestamp.range  start it at the first day the trail has data
--
-- S3 layout assumed:
--   s3://<BUCKET>/<PREFIX>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<region>/yyyy/MM/dd/*.json.gz
--
-- No partition maintenance is needed -- projection resolves partitions at query time.
-- =========================================================================================

CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail.cloudtrail_logs (
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
    tlsdetails         STRUCT<
        tlsversion:               STRING,
        ciphersuite:              STRING,
        clientprovidedhostheader: STRING>
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

    -- All 34 regions in the `aws` (commercial) partition. GovCloud is deliberately
    -- excluded; it is a separate partition and never lands in a commercial trail bucket.
    'projection.region.type'             = 'enum',
    'projection.region.values'           = 'af-south-1,ap-east-1,ap-east-2,ap-northeast-1,ap-northeast-2,ap-northeast-3,ap-south-1,ap-south-2,ap-southeast-1,ap-southeast-2,ap-southeast-3,ap-southeast-4,ap-southeast-5,ap-southeast-6,ap-southeast-7,ca-central-1,ca-west-1,eu-central-1,eu-central-2,eu-north-1,eu-south-1,eu-south-2,eu-west-1,eu-west-2,eu-west-3,il-central-1,me-central-1,me-south-1,mx-central-1,sa-east-1,us-east-1,us-east-2,us-west-1,us-west-2',

    'projection.timestamp.type'          = 'date',
    'projection.timestamp.format'        = 'yyyy/MM/dd',
    'projection.timestamp.interval'      = '1',
    'projection.timestamp.interval.unit' = 'DAYS',
    'projection.timestamp.range'         = '2024/01/01,NOW',

    'storage.location.template'          = 's3://<BUCKET>/<PREFIX>/AWSLogs/<ACCOUNT_ID>/CloudTrail/${region}/${timestamp}'
);

-- Notes
--   * `region` must be a partition key because projection templates cannot wildcard a
--     path segment. The generated queries only prune on `timestamp`, so Athena probes all
--     34 regions for each day in range. Trim `projection.region.values` to the regions
--     the trail actually writes, or add `AND region IN (...)` by hand.
--   * Keep every enabled region in the list, including ones the SCP is meant to deny --
--     those are exactly the rows this analysis is looking for. A region missing from the
--     enum returns no rows, which reads as "the SCP blocks nothing there."
--   * Opt-in regions (af-south-1, ap-east-*, ap-southeast-3..7, eu-central-2, eu-south-*,
--     il-central-1, me-*, mx-central-1, ca-west-1) only have a prefix once enabled, so
--     listing them costs a wasted probe per day but never a wrong answer.
--   * China (cn-north-1, cn-northwest-1) is left out for the same reason as GovCloud --
--     separate partition, separate trail bucket. Swap the enum if this is an aws-cn org.
--   * `projection.timestamp.range` bounds the scan. Starting it years before the trail
--     exists costs listing time on every query.
