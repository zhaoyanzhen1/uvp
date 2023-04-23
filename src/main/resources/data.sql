BEGIN;

-- The source names MUST be the same as those defined in VulnSource.java
-- The config keys MUST be the same as those defined in VulnSourceConfig.ConfigKey
-- It's recommended to encrypt sensitive data before saving to database. See encryption.md
INSERT INTO vuln_source_config(source, import_enabled, config) VALUES
('OSV', true, '{}'::jsonb),
('NVD', true, '{}'::jsonb),
('OSS_INDEX', true, '{}'::jsonb),
('VTOPIA', false, '{}'::jsonb)
ON CONFLICT (source) DO NOTHING;

-- The job names MUST be the same as those defined in QuartzJobEnum.java
INSERT INTO quartz_job_config(job, cron) VALUES
('DUMP_VULN_JOB', '0 0 2 * * ? *'),
('CAPTURE_CRON_JOB', '*/10 * * * * ? *')
ON CONFLICT (job) DO NOTHING;

-- Create gin indexes to speed up 'LIKE' condition filter.
-- It takes more time to dump data on an empty database with the following indexes,
-- so it's recommended to 1. drop these indexes 2. dump data 3. re-build these indexes.
create extension if not exists pg_trgm;
create index if not exists ap_name_trgm_idx on affected_package using gin (name gin_trgm_ops);
create index if not exists ap_purl_trgm_idx on affected_package using gin (purl gin_trgm_ops);
create index if not exists vuln_vuln_id_trgm_idx on vulnerability using gin (vuln_id gin_trgm_ops);
create index if not exists alias_alias_trgm_idx on alias using gin (alias gin_trgm_ops);

COMMIT;
