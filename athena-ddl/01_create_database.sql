-- Glue database that holds the CloudTrail table.
-- Matches the --database default used in the README (`cloudtrail`).
--
-- TEMPLATE-ONLY BEGIN
-- `<TOKENS>` are filled in by render_ddl.py. Fill them by hand if you are only
-- setting up one trail.
-- TEMPLATE-ONLY END

CREATE DATABASE IF NOT EXISTS <DATABASE>
COMMENT 'CloudTrail logs for SCP impact analysis';
