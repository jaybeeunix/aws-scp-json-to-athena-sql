-- =========================================================================================
-- <DATABASE>.<ACCOUNTS_TABLE> -- the organization's accounts and where they sit in the OU
-- tree. Built by dump_org_accounts.sh; see that script for the upload command.
--
-- Why this exists: SCPs attach to OUs, not to accounts. With 2400 members, "which
-- accounts does this SCP break" is an unreadable answer and "which OUs does it break" is
-- the one you can act on. Pass --accounts-table <DATABASE>.<ACCOUNTS_TABLE> to
-- scp_to_athena.py and the generated summaries join against this and group by ou_path.
--
-- It also replaces the --accounts flag. Scoping a run to one OU is a predicate here
-- (ou_path LIKE 'Root/Production/%') rather than 2400 account IDs on a command line.
--
-- TEMPLATE-ONLY BEGIN
-- `<TOKENS>` are filled in by render_ddl.py from a CSV row. By hand:
--     <BUCKET>/<PREFIX>  where you uploaded org_accounts.csv -- a prefix of its own,
--                        containing nothing else; this table reads every object under it
-- TEMPLATE-ONLY END
-- =========================================================================================

CREATE EXTERNAL TABLE IF NOT EXISTS <DATABASE>.<ACCOUNTS_TABLE> (
    account_id     STRING,
    account_name   STRING,
    account_email  STRING,
    account_status STRING,
    ou_id          STRING,
    ou_name        STRING,
    -- Root-to-leaf, slash separated: 'Root/Production/Platform'. LIKE against this is
    -- the cheap way to select an OU subtree, which is how SCP inheritance works.
    ou_path        STRING
)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.OpenCSVSerde'
WITH SERDEPROPERTIES (
    'separatorChar' = ',',
    'quoteChar'     = '"',
    'escapeChar'    = '\\'
)
STORED AS TEXTFILE
LOCATION 's3://<BUCKET>/<PREFIX>/org_accounts/'
TBLPROPERTIES ('skip.header.line.count' = '1');

-- Notes
--   * OpenCSVSerde reads every column as STRING regardless of what you declare, which is
--     what we want -- account_id must stay a string or the leading zeros that about 1 in
--     10 account IDs carry are lost, and the join to recipientaccountid stops matching.
--   * A few hundred KB. It is read on every join, but it is small enough that the cost
--     is the file open, not the scan.
--   * Re-upload it when the org changes; accounts move between OUs and a stale ou_path
--     attributes impact to the wrong team. The CSV carries its generation time in a
--     header comment, which skip.header.line.count hides from the table.

-- Sanity check after loading. Row count should match `aws organizations list-accounts`,
-- and no ou_path should be empty -- a blank one means dump_org_accounts.sh could not walk
-- that account's parents, usually a permissions problem rather than a real orphan.
SELECT count(*)                              AS accounts,
       count_if(ou_path = '')                AS missing_ou_path,
       count_if(account_status <> 'ACTIVE')  AS not_active,
       count(DISTINCT ou_path)               AS distinct_ous
FROM <DATABASE>.<ACCOUNTS_TABLE>;
