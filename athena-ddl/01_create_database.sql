-- Glue database that holds the CloudTrail table.
-- Matches the --database default used in the README (`cloudtrail`).

CREATE DATABASE IF NOT EXISTS cloudtrail
COMMENT 'CloudTrail logs for SCP impact analysis';
