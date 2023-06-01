package org.opensourceway.uvp.schedule.job;

import org.jetbrains.annotations.NotNull;
import org.opensourceway.uvp.service.VulnPushService;
import org.quartz.JobExecutionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.quartz.QuartzJobBean;

public class PushVulnJob extends QuartzJobBean {
    private static final Logger logger = LoggerFactory.getLogger(PushVulnJob.class);

    @Autowired
    private VulnPushService vulnPushService;

    @Override
    protected void executeInternal(@NotNull JobExecutionContext context) {
        logger.info("Launch PushVulnJob.");
        try {
            vulnPushService.pushVuln();
        } catch (Exception e) {
            logger.error("Exception occurs when execute PushVulnJob", e);
        }
        logger.info("Finish PushVulnJob.");
    }
}
