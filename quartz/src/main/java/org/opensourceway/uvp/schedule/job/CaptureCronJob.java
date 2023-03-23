package org.opensourceway.uvp.schedule.job;

import jakarta.annotation.PostConstruct;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.opensourceway.uvp.entity.QuartzJobConfig;
import org.opensourceway.uvp.enums.QuartzJobEnum;
import org.opensourceway.uvp.schedule.constant.QuartzConstant;
import org.opensourceway.uvp.utility.QuartzJobConfigUtil;
import org.quartz.CronScheduleBuilder;
import org.quartz.JobExecutionContext;
import org.quartz.Scheduler;
import org.quartz.Trigger;
import org.quartz.TriggerBuilder;
import org.quartz.TriggerKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.scheduling.quartz.QuartzJobBean;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Proactively capture changes of {@link QuartzJobConfig#getCron()}.
 * If cron changes, then reschedule corresponding job.
 */
public class CaptureCronJob extends QuartzJobBean {

    private static final Logger logger = LoggerFactory.getLogger(CaptureCronJob.class);

    private static final Map<QuartzJobEnum, String> jobToCron = new HashMap<>();

    @Autowired
    private QuartzJobConfigUtil quartzJobConfigUtil;

    @Autowired
    private ApplicationContext context;

    /**
     * Record the crons when this job was initialized for the first time.
     */
    @PostConstruct
    private void recordCron() {
        Arrays.stream(QuartzJobEnum.values()).forEach(job ->
                jobToCron.putIfAbsent(job, quartzJobConfigUtil.getJobCron(job)));
    }

    protected void executeInternal(@NotNull JobExecutionContext quartzJobContext) {
        Arrays.stream(QuartzJobEnum.values()).forEach(this::captureChange);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void captureChange(QuartzJobEnum job) {
        var oldCron = jobToCron.get(job);
        var newCron = quartzJobConfigUtil.getJobCron(job);

        if (StringUtils.equals(oldCron, newCron)) {
            return;
        }

        Scheduler scheduler = (Scheduler) context.getBean(QuartzConstant.QUARTZ_SCHEDULER);
        Trigger oldTrigger;
        try {
            oldTrigger = scheduler.getTrigger(TriggerKey.triggerKey(QuartzConstant.JOB_TO_TRIGGER.get(job)));
        } catch (Exception e) {
            // If no trigger is found, it means the job is not configured in QuartzJobConfigure.
            return;
        }

        try {
            TriggerBuilder builder = oldTrigger.getTriggerBuilder();
            var trigger = builder.withSchedule(CronScheduleBuilder.cronSchedule(newCron)).build();
            scheduler.rescheduleJob(oldTrigger.getKey(), trigger);
        } catch (Exception e) {
            // If failed to change import cron, former trigger will be kept.
            logger.warn("Failed to change cron for <{}> from <{}> to <{}>", job, oldCron, newCron);
            return;
        }

        jobToCron.put(job, newCron);
        logger.info("Import cron for <{}> is changed from <{}> to <{}>", job, oldCron, newCron);
    }
}
