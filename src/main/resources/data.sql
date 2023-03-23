BEGIN;

-- The source names MUST be the same as those defined in VulnSource.java
-- The config keys MUST be the same as those defined in VulnSourceConfig.ConfigKey
-- It's recommended to encrypt sensitive data before saving to database. See encryption.md
INSERT INTO vuln_source_config(source, import_enabled, config) VALUES
('OSV', true, '{}'::jsonb),
('NVD', true, '{}'::jsonb),
('OSS_INDEX', true, '{}'::jsonb),
('VTOPIA', false, '{}'::jsonb),
('PRISM_7_CAI', false, '{}'::jsonb)
ON CONFLICT (source) DO NOTHING;

-- The job names MUST be the same as those defined in QuartzJobEnum.java
INSERT INTO quartz_job_config(job, cron) VALUES
('DUMP_VULN_JOB', '0 0 2 * * ? *'),
('CAPTURE_CRON_JOB', '*/10 * * * * ? *')
ON CONFLICT (job) DO NOTHING;

COMMIT;
