package org.opensourceway.uvp.schedule.job;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.uvp.batch.job.BatchJobConfig;
import org.quartz.JobExecutionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.quartz.QuartzJobBean;

public class DumpVulnJob extends QuartzJobBean {
    private static final Logger logger = LoggerFactory.getLogger(DumpVulnJob.class);

    @Autowired
    private BatchJobConfig batchJobConfig;

    protected void executeInternal(@NotNull JobExecutionContext quartzJobContext) {
        logger.info("Launch DumpVulnJob.");

        try {
            batchJobConfig.launchDumpJob();
        } catch (Exception e) {
            logger.error("Exception occurs when execute DumpVulnJob", e);
        }
        logger.info("Finish DumpVulnJob.");
    }
}
