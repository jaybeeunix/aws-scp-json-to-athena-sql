-- =========================================================================================
-- cloudtrail.cloudtrail_logs_ymd -- manual year/month/day partitions
--
-- Use when you cannot use partition projection (e.g. the table is maintained by a Glue
-- crawler, or you only want a few specific days registered).
--
--     ./scp_to_athena.py ... --table cloudtrail_logs_ymd --partition-style ymd
--
-- Partitions are NOT auto-discovered: MSCK REPAIR TABLE does not work here because the
-- S3 path is not Hive-style (no `year=2025/`). Register each day explicitly -- see the
-- ALTER TABLE block at the bottom.
-- =========================================================================================

CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail.cloudtrail_logs_ymd (
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
    year  STRING,
    month STRING,
    day   STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://<BUCKET>/<PREFIX>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<REGION>/';

-- One day, one region:
ALTER TABLE cloudtrail.cloudtrail_logs_ymd ADD IF NOT EXISTS
    PARTITION (year = '2025', month = '06', day = '01')
    LOCATION 's3://<BUCKET>/<PREFIX>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<REGION>/2025/06/01/';

-- A whole range is tedious by hand. Generate the statements instead:
--
--   d=2025-06-01; end=2025-09-09
--   while [[ "$d" < "$end" || "$d" == "$end" ]]; do
--     y=${d:0:4} m=${d:5:2} dd=${d:8:2}
--     echo "ALTER TABLE cloudtrail.cloudtrail_logs_ymd ADD IF NOT EXISTS PARTITION (year='$y', month='$m', day='$dd') LOCATION 's3://<BUCKET>/<PREFIX>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<REGION>/$y/$m/$dd/';"
--     d=$(date -I -d "$d + 1 day")
--   done
--
-- Note this table is pinned to ONE region by its LOCATION. For multi-region coverage
-- either add a region partition key (and a region segment to each partition LOCATION),
-- or prefer the projection tables in 02/03 -- which is why those are the default.
