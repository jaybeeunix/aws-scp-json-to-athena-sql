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
    year  STRING,
    month STRING,
    day   STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://<BUCKET>/<PREFIX>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<REGION>/';

-- Register the days in the analysis window. Athena takes many PARTITION clauses per
-- ALTER, so these are batched; run each statement separately in the console.
<ADD_PARTITIONS>

-- Note this table is pinned to ONE region by its LOCATION. For multi-region coverage
-- either add a region partition key (and a region segment to each partition LOCATION),
-- or prefer the projection tables in 02/03 -- which is why those are the default.
