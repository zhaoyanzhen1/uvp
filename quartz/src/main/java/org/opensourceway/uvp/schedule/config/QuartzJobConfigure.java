package org.opensourceway.uvp.schedule.config;

import org.opensourceway.uvp.enums.QuartzJobEnum;
import org.opensourceway.uvp.schedule.constant.QuartzConstant;
import org.opensourceway.uvp.schedule.job.CaptureCronJob;
import org.opensourceway.uvp.schedule.job.DumpVulnJob;
import org.opensourceway.uvp.utility.QuartzJobConfigUtil;
import org.opensourceway.uvp.utility.VulnSourceConfigUtil;
import org.quartz.CronScheduleBuilder;
import org.quartz.JobBuilder;
import org.quartz.JobDetail;
import org.quartz.Trigger;
import org.quartz.TriggerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class QuartzJobConfigure {

    @Autowired
    private VulnSourceConfigUtil vulnSourceConfigUtil;

    @Autowired
    private QuartzJobConfigUtil quartzJobConfigUtil;

    @Bean
    public JobDetail captureCronJobDetail() {
        return JobBuilder.newJob(CaptureCronJob.class)
                .withIdentity(QuartzConstant.CAPTURE_CRON_JOB_DETAIL_ID)
                .storeDurably()
                .build();
    }

    @Bean
    public Trigger captureCronJobTrigger() {
        return TriggerBuilder.newTrigger()
                .forJob(captureCronJobDetail())
                .withIdentity(QuartzConstant.CAPTURE_CRON_TRIGGER_ID)
                .startNow()
                .withSchedule(CronScheduleBuilder.cronSchedule(quartzJobConfigUtil.getJobCron(QuartzJobEnum.CAPTURE_CRON_JOB)))
                .build();
    }

    @Bean
    public JobDetail dumpVulnJobDetail() {
        return JobBuilder.newJob(DumpVulnJob.class)
                .withIdentity(QuartzConstant.DUMP_VULN_JOB_DETAIL_ID)
                .storeDurably()
                .build();
    }

    @Bean
    public Trigger dumpVulnJobTrigger() {
        return TriggerBuilder.newTrigger()
                .forJob(dumpVulnJobDetail())
                .withIdentity(QuartzConstant.DUMP_VULN_JOB_TRIGGER_ID)
                .startNow()
                .withSchedule(CronScheduleBuilder.cronSchedule(quartzJobConfigUtil.getJobCron(QuartzJobEnum.DUMP_VULN_JOB)))
                .build();
    }

}
