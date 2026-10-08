-- =========================================================================================
-- cloudtrail.cloudtrail_logs_org -- ORGANIZATION trail, partition projection
--
-- This is the one you want for SCP impact analysis: an org trail carries every member
-- account, so `recipientaccountid` in the generated queries is meaningful.
--
--     ./scp_to_athena.py ... --database cloudtrail --table cloudtrail_logs_org
--
-- Replace before running:
--     <BUCKET>, <PREFIX>   S3 bucket / prefix of the org trail
--     <ORG_ID>             o-xxxxxxxxxx
--     projection.account_id.values   comma-separated member account IDs, no spaces
--     projection.timestamp.range     first day the trail has data
--
-- S3 layout assumed:
--   s3://<BUCKET>/<PREFIX>/AWSLogs/<ORG_ID>/<account-id>/CloudTrail/<region>/yyyy/MM/dd/
-- =========================================================================================

CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail.cloudtrail_logs_org (
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
    account_id  STRING,
    region      STRING,
    `timestamp` STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://<BUCKET>/<PREFIX>/AWSLogs/<ORG_ID>/'
TBLPROPERTIES (
    'projection.enabled'                 = 'true',

    'projection.account_id.type'         = 'enum',
    'projection.account_id.values'       = '111111111111,222222222222,333333333333',

    'projection.region.type'             = 'enum',
    'projection.region.values'           = 'us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,eu-west-1,eu-west-2,eu-west-3,eu-central-1,eu-north-1,eu-south-1,ap-south-1,ap-northeast-1,ap-northeast-2,ap-northeast-3,ap-southeast-1,ap-southeast-2,sa-east-1',

    'projection.timestamp.type'          = 'date',
    'projection.timestamp.format'        = 'yyyy/MM/dd',
    'projection.timestamp.interval'      = '1',
    'projection.timestamp.interval.unit' = 'DAYS',
    'projection.timestamp.range'         = '2024/01/01,NOW',

    'storage.location.template'          = 's3://<BUCKET>/<PREFIX>/AWSLogs/<ORG_ID>/${account_id}/CloudTrail/${region}/${timestamp}'
);

-- Notes
--   * accounts x regions x days is the number of S3 prefixes Athena probes when nothing
--     but `timestamp` is filtered. 50 accounts x 18 regions x 100 days = 90k prefixes,
--     which is slow. Two ways to cut it down, both worth doing:
--       - list only the accounts in scope for the SCP in `projection.account_id.values`
--         (and the same set in `--accounts` so the row filter matches), and
--       - trim `projection.region.values` to regions the org actually uses.
--   * The management account is in the trail but SCPs never apply to it. Leave it out of
--     the enum, or pass `--exclude-accounts <mgmt-account-id>` to the generator.
--   * If the account list changes often, ALTER TABLE SET TBLPROPERTIES the enum rather
--     than recreating the table. There is no projection type that enumerates a prefix.
