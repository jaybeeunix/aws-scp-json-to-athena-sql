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
